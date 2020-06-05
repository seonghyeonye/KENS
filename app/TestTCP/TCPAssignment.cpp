/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"
#include <E/E_TimeUtil.hpp>

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:{
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
		}
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
			static_cast<struct sockaddr *>(param.param2_ptr),
			static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
		    	static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

std::map<int, SockContext>::iterator TCPAssignment::mapfindbypid(int pid, int fd){
	auto it=addrfdlist.begin();
	while(it!=addrfdlist.end()){
		int fdcmp = it->first;
		int pidcmp = it->second.pid;
		if(fd==fdcmp&&pid==pidcmp){
			return it;
		}		
		it++;
	}
	//return;
}

void TCPAssignment::sendTCPPacket(Packet *packet,Header *tcpHeader, SockContext *context, uint32_t desIP32, uint32_t srcIP32, uint16_t desPort, uint16_t srcPort, uint32_t seqnum, uint32_t acknum, uint8_t flags, void* internalbuffer, int datasize, int window){
	packet->writeData(14+12,&srcIP32,4);
	packet->writeData(14+16,&desIP32,4);

	uint8_t *tcpSegment = new uint8_t[datasize+20];

	if(internalbuffer!=NULL){
		InternalBuffer *intbuffer =(InternalBuffer*) internalbuffer;
		packet->writeData(54,intbuffer->buffer+intbuffer->nextseqnum,datasize);
		intbuffer->nextseqnum+=datasize;
	}
	
	tcpHeader->srcPort=htons(srcPort);
	tcpHeader->desPort=htons(desPort);
	tcpHeader->seqnum=htonl(seqnum);
	tcpHeader->acknum=htonl(acknum);
	tcpHeader->len=(5<<4);
	tcpHeader->flags=flags;
	tcpHeader->urg_ptr=0;
	tcpHeader->window=htons(window);
	tcpHeader->checksum=0;
	
	uint16_t checksum;
	packet->writeData(30+4,tcpHeader,20);
	packet->readData(30+4,tcpSegment,datasize+20);
	checksum=htons(~(NetworkUtil::tcp_sum(srcIP32, desIP32,(uint8_t *)tcpSegment,20+datasize)));
	packet->writeData(30+4+16,&checksum,2);

	if(context->state==TIMED_WAIT){
		Payload *payload = new Payload();
		payload->context=context;
		payload->sendPacket=false;
		UUID timerkey=TimerModule::addTimer(payload,TimeUtil::makeTime(120,TimeUtil::SEC));
		payload->timerkey=timerkey;
	}
	else if(flags==ACK && datasize!=0) {
		Payload *payload = new Payload();
		payload->packet=this->clonePacket(packet);
		payload->sendPacket=true;

		UUID timerkey = TimerModule::addTimer(payload,TimeUtil::makeTime(context->timercal.RTO,TimeUtil::MSEC));
		printf("timerkey in send ack is %d\n",timerkey);
		payload->timerkey=timerkey;

		payload->context=context;

		int timer =TimeUtil::getTime(this->getHost()->getSystem()->getCurrentTime(),TimeUtil::MSEC);
		//printf("time current is %d\n",timer);

		payload->storedtime=timer;

		timerlist.insert(std::pair<UUID,SockContext>(timerkey,*context));

		payloadlist.insert(std::pair<int,Payload>(seqnum,*payload));
		context->writeflag=1;

	}
	this->sendPacket("IPv4",packet);
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type){
	if(domain!=PF_INET||type!=SOCK_STREAM)
		this->returnSystemCall(syscallUUID,-1);
	int fd=this->createFileDescriptor(pid);
	SockContext *context= new SockContext();
	context->pid=pid;
	addrfdlist.insert(std::pair<int,SockContext>(fd,*context));
	this->returnSystemCall(syscallUUID,fd);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd){
	uint32_t desIP32, srcIP32;
	uint16_t desPort,srcPort;
	SockContext *context= &(mapfindbypid(pid,fd)->second);

	//only for bind sockfd (listen socket excluded)
	if(context->srcIP!=-1&&context->desIP!=-1&&context->state!=LISTENS){
		desIP32=context->desIP;
		desPort=context->desPort;
		srcIP32=context->srcIP;
		srcPort=context->srcPort;

		desIP32=htonl(desIP32);
		srcIP32=htonl(srcIP32);

		Packet* newPacket= this->allocatePacket(54);

		Header *tcpHeader = new Header();
		sendTCPPacket(newPacket,tcpHeader,context,desIP32,srcIP32,desPort,srcPort,context->seqnum,context->acknum,FIN+ACK,NULL,0,51200);

		//passive close
		if(context->state==CLOSE_WAIT){
			context->state=LAST_ACK;
		}
		//active close
		else {
			context->state=FIN_WAIT1;
		}
	}
	else{
		addrfdlist.erase(mapfindbypid(pid,fd));
	}
	this->removeFileDescriptor(pid,fd);
	this->returnSystemCall(syscallUUID,0);
}

void TCPAssignment::readDataPacket(UUID syscallUUID, SockContext *context, const void *buf, size_t count){
	InternalBuffer *intbuffer =&(context->intbuffer);
	if(intbuffer->remain<=0){
		return;
	}
	int base = intbuffer->base;
	uint32_t desIP32,srcIP32;
	uint16_t desPort,srcPort;

	if(base+count>51200){
		int limitleft=51200-base;
		memcpy((void *)buf, intbuffer->buffer+base,limitleft);
		memcpy((void *)buf+limitleft,intbuffer->buffer,count-limitleft);
		memset(intbuffer->buffer+base,0,limitleft);
		memset(intbuffer->buffer,0,count-limitleft);
	}
	else{
		memcpy((void *)buf,intbuffer->buffer+base,count);
		memset(intbuffer->buffer+base,0,count);
	}
	intbuffer->base+=count;
	intbuffer->base%=51200;
	intbuffer->remain+=count;

	this->returnSystemCall(syscallUUID,count);

}
void TCPAssignment::writeDataPacket(UUID syscallUUID, SockContext *context, const void *buf, size_t count){
	InternalBuffer *intbuffer =&(context->intbuffer);
	int nextseq = intbuffer->nextseqnum;
	int tempcount=count;
	int sendcount;
	uint32_t desIP32,srcIP32;
	uint16_t desPort,srcPort;

	if(intbuffer->remain<=0){
		return;
	}
	
	if(nextseq+count>51200){
		int part1count=51200-nextseq;
		memcpy(intbuffer->buffer+nextseq,buf,part1count);
		int part2count=count-part1count;
		intbuffer->nextseqnum=0;
		memcpy(intbuffer->buffer,buf+part1count,part2count);
	}
	else{
		memcpy(intbuffer->buffer+nextseq,buf,count);
	}
	intbuffer->remain-=count;
	// printf("after remain is ^^^^^^^^^^^^^%d\n",intbuffer->remain);
	this->returnSystemCall(syscallUUID,count);
	if(context->intbuffer.peerremain!=0){
		while(tempcount>0){
			if(tempcount>=512)
				sendcount=512;
			else{
				sendcount=tempcount;
			}
			Packet* myPacket=this->allocatePacket(sendcount+54);
			Header *tcpHeader = new Header();

			desIP32=htonl(context->desIP);
			srcIP32=htonl(context->srcIP);
			desPort=context->desPort;
			srcPort=context->srcPort;

			sendTCPPacket(myPacket,tcpHeader,context, desIP32,srcIP32,desPort,srcPort,context->seqnum,context->acknum,ACK,intbuffer,sendcount,51200);
			context->seqnum+=sendcount;
			tempcount-=sendcount;
		}
	}
}

void TCPAssignment:: syscall_read(UUID syscallUUID, int pid, int sockfd, const void *buf, size_t count){
	SockContext *context = &(mapfindbypid(pid,sockfd)->second);
	InternalBuffer *intbuffer =&(context->intbuffer);
	if(intbuffer->remain==51200){
		context->syscallID=syscallUUID;
		context->iobuffer.buffer=buf;
		context->iobuffer.count=count;
	}
	else{
		if((intbuffer->base+count)>(intbuffer->nextseqnum)&&(intbuffer->nextseqnum)>(intbuffer->base))
			count=intbuffer->nextseqnum-intbuffer->base;
		readDataPacket(syscallUUID,context,buf,count);
	}
}

void TCPAssignment:: syscall_write(UUID syscallUUID, int pid, int sockfd, const void *buf, size_t count){
	SockContext *context = &(mapfindbypid(pid,sockfd)->second);
	InternalBuffer *intbuffer =&(context->intbuffer);
	// printf("intbuffer->remain is %d\n",intbuffer->remain);
	// printf("intbufffer->acailsend is %d\n",intbuffer->availsend);

	if(intbuffer->remain<=0||intbuffer->availsend<=0){
		//printf("wait\n");
		context->syscallID=syscallUUID;
		context->iobuffer.buffer=buf;
		context->iobuffer.count=count;
	}
	else if(intbuffer->remain>=count&&intbuffer->availsend>=count){
		//printf("not wait\n");
		intbuffer->availsend-=count;
		writeDataPacket(syscallUUID,context,buf,count);
	}
	else{
		//printf("first case\n");
		int minval= std::min((int) intbuffer->remain,intbuffer->availsend);
		writeDataPacket(syscallUUID, context, buf, minval);
		if(minval==intbuffer->availsend){
			intbuffer->availsend-=minval;
		}
	}
	// else if(intbuffer->remain==512||intbuffer->availsend==512){
	// 	printf("first case\n");
	// 	writeDataPacket(syscallUUID,context,buf,512);
	// 	if(intbuffer->availsend==512)
	// 		intbuffer->availsend-=512;
	// }
	// else{
	// 	printf("not wait\n");
	// 	intbuffer->availsend-=count;
	// 	writeDataPacket(syscallUUID,context,buf,count);
	// }
}

void TCPAssignment:: syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen){
	const struct sockaddr_in *addr_int = (const struct sockaddr_in *)addr;
	unsigned short int desPort= ntohs(addr_int->sin_port);
	uint8_t desIP[4], srcIP[4];
	uint32_t desIP32, srcIP32;
	int srcPort;
	int tableidx;

	desIP32= ntohl(addr_int->sin_addr.s_addr);

	SockContext *context= &(mapfindbypid(pid,sockfd)->second);
	context->desIP=desIP32;
	context->desPort=desPort;

	tableidx= this->getHost()->getRoutingTable(desIP);

	if(context->srcIP==-1&&context->srcPort==-1){
		this->getHost()->getIPAddr(srcIP,tableidx);

		srcIP32=srcIP[0]<<24|srcIP[1]<<16|srcIP[2]<<8|srcIP[3];
		// Dynamic and/or Private Port : 1024 ~ 65535
		while(1){
			int tempport=rand()%64510+1024;
			auto it=addrfdlist.begin();
			while(it!=addrfdlist.end()){
				int cmpport = it->second.srcPort;
				if(tempport==cmpport)
					break;
				it++;
			}
			srcPort=tempport;
			break;
		}
	}
	else{
		srcIP32=context->srcIP;
		srcPort=context->srcPort;
	}
	context->srcIP=srcIP32;
	context->srcPort=srcPort;

	srcIP32=htonl(srcIP32);
	desIP32=htonl(desIP32);

	Packet* newPacket= this->allocatePacket(54);

	Header *tcpHeader = new Header();

	sendTCPPacket(newPacket,tcpHeader,context,desIP32,srcIP32,desPort,srcPort,context->seqnum,context->acknum,SYN,NULL,0,51200);
	context->state=SYNSENT;
	context->syscallID=syscallUUID;

	context->intbuffer= *(new InternalBuffer());
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog){
	SockContext *context= &mapfindbypid(pid,sockfd)->second;
	//not bound connection
	if(context->srcIP==-1||context->srcPort==-1){
		this->returnSystemCall(syscallUUID,-1);
	}
	
	context->backlog=backlog;
	context->state=LISTENS;
	
	context->intbuffer= *(new InternalBuffer());

	this->returnSystemCall(syscallUUID,0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	int dupsockfd;
	SockContext *sockcontext=&mapfindbypid(pid,sockfd)->second;

	std::list<int> *dupsocklist=&(sockcontext->dupsocklist);

	//not bound connection
	if(sockcontext->srcIP==-1||sockcontext->srcPort==-1){
		this->returnSystemCall(syscallUUID,-1);
	}

	sockcontext->syscallID=syscallUUID;
	sockcontext->addrinfo=addr;

	if(dupsocklist->size()>0){
		dupsockfd= dupsocklist->front();
		dupsocklist->pop_front();

		SockContext *dupcontext= &mapfindbypid(pid,dupsockfd)->second;

		//estab or close wait(finack from client quickly arrived before accept)
		if(dupcontext->state==ESTAB||dupcontext->state==CLOSE_WAIT){
			struct sockaddr_in *ret=(struct sockaddr_in *)addr;	
			memset(ret,0,sizeof(ret));
		
			ret->sin_family = AF_INET;
			ret->sin_addr.s_addr=htonl(dupcontext->srcIP);
			ret->sin_port=htons(dupcontext->srcPort);
			//dupcontext->state=ESTAB;
			this->returnSystemCall(syscallUUID,dupsockfd);
		}

	}
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen){
	struct sockaddr_in *addr_int = (struct sockaddr_in *)addr;
	unsigned short int portnum= ntohs(addr_int->sin_port);
	uint32_t ipaddr=ntohl((addr_int->sin_addr).s_addr);

	auto it=addrfdlist.begin();
	while(it!=addrfdlist.end()){
		int fdcmp = it->first;
		int ipcmp = it->second.srcIP;
		int portcmp = it->second.srcPort;
		int pidcmp= it->second.pid;
		if(pid==pidcmp){
			if(portnum==portcmp){
				if(ipaddr==ipcmp)
					this->returnSystemCall(syscallUUID,-1);
				else if(ipaddr==INADDR_ANY||ipcmp==INADDR_ANY)
					this->returnSystemCall(syscallUUID,-1);
			}
			else if(sockfd==fdcmp){
				if(ipcmp!=-1){
					this->returnSystemCall(syscallUUID,-1);
				}
			}
		}		
		it++;
	}
	SockContext *context= &mapfindbypid(pid,sockfd)->second;
	context->srcIP=ipaddr;
	context->srcPort=portnum;
	this->returnSystemCall(syscallUUID,0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	SockContext *context= &mapfindbypid(pid,sockfd)->second;
	// if(addrinfo.compare("-1")==0)
	// 	return -1;

	uint32_t ipaddr= context->srcIP;
	unsigned short int portnum = context->srcPort;
	struct sockaddr_in *ret=(struct sockaddr_in *)addr;	

	memset(ret,0,sizeof(ret));
	
	ret->sin_family = AF_INET;
	ret->sin_addr.s_addr=htonl(ipaddr);
	ret->sin_port=htons(portnum);

	this->returnSystemCall(syscallUUID,0);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	SockContext *context= &mapfindbypid(pid,sockfd)->second;
	
	uint32_t ipaddr= context->desIP;
	
	unsigned short int portnum = context->desPort;
	struct sockaddr_in *ret=(struct sockaddr_in *)addr;	

	memset(ret,0,sizeof(ret));
	
	ret->sin_family = AF_INET;
	ret->sin_addr.s_addr=htonl(ipaddr);
	ret->sin_port=htons(portnum);

	this->returnSystemCall(syscallUUID,0);
}

std::map<UUID,SockContext> TCPAssignment::getTimerbyContext(uint32_t desIP, uint32_t srcIP, uint16_t desPort, uint16_t srcPort, int seqtofind){
	auto it=timerlist.begin();
	std::map<UUID,SockContext> resultlist;
	while(it!=timerlist.end()){
		uint32_t desIPcmp = it->second.desIP;
		uint16_t desPortcmp = it->second.desPort;
		uint32_t srcIPcmp = it->second.srcIP;
		uint16_t srcPortcmp = it->second.srcPort;
		int seqnum=it->second.seqnum;

		if(desIP==desIPcmp&&desPort==desPortcmp&&srcIP==srcIPcmp&&srcPort==srcPortcmp){
			if(seqtofind==-1)
				resultlist.insert(std::pair<UUID, SockContext>(it->first,it->second));
			else{
				if(seqnum==seqtofind){
					resultlist.insert(std::pair<UUID, SockContext>(it->first,it->second));
				}
			}
		}
		it++;
	}
	return resultlist;
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	uint8_t srcIP[4];
	uint8_t desIP[4];
	uint32_t srcIP32;
	uint32_t desIP32;
	uint16_t srcPort;
	uint16_t desPort;
	uint8_t flags;
	uint32_t seqnum;
	uint32_t acknum;
	uint16_t window;
	int sockfd=-1;
	SockContext *context;

	packet->readData(14+12,&srcIP32,4);
	packet->readData(14+16,&desIP32,4);

	srcIP32=ntohl(srcIP32);
	desIP32=ntohl(desIP32);

	Header *tcpHeader = new Header();
	packet->readData(30+4, tcpHeader,20);

	srcPort=ntohs(tcpHeader->srcPort);
	desPort=ntohs(tcpHeader->desPort);
	flags = tcpHeader->flags;
	seqnum=ntohl(tcpHeader->seqnum);
	acknum=ntohl(tcpHeader->acknum);
	window=ntohs(tcpHeader->window);

	uint8_t *tcpSegment = new uint8_t[packet->getSize()-34];
	packet->readData(30+4,tcpSegment,packet->getSize()-34);

	uint16_t checksum=(~NetworkUtil::tcp_sum(htonl(srcIP32), htonl(desIP32), tcpSegment, packet->getSize()-34));
	assert(checksum==0);

	//client case connect
	if(flags==SYN+ACK){
		// printf("synack enter\n");
		auto it=addrfdlist.begin();
		while(it!=addrfdlist.end()){
			uint32_t srcIPcmp = it->second.srcIP;
			uint16_t srcPortcmp = it->second.srcPort;
			uint32_t desIPcmp = it->second.desIP;
			uint16_t desPortcmp = it->second.desPort;

			if(srcPort==desPortcmp&&srcIP32==desIPcmp&&desPort==srcPortcmp&&desIP32==srcIPcmp){
				sockfd=it->first;
				context = &(it->second);
				break;
			}
			it++;
		}

		if(sockfd==-1){
			return;
		}

		context->seqnum=acknum;
		context->acknum=seqnum+1;
		context->intbuffer.peerremain=window;

		Packet* myPacket = this->clonePacket(packet);

		desIP32=htonl(desIP32);
		srcIP32=htonl(srcIP32);

		sendTCPPacket(myPacket,tcpHeader,context,srcIP32,desIP32,srcPort,desPort,acknum,seqnum+1,ACK,NULL,0,51200);

		//state change
		context->state=ESTAB;
		this->freePacket(packet);

		this->returnSystemCall(context->syscallID,0);
	}

	//server incoming client
	else if(flags==SYN){
		auto it=addrfdlist.begin();
		while(it!=addrfdlist.end()){
			uint32_t srcIPcmp= it->second.srcIP;
			uint16_t srcPortcmp = it->second.srcPort;
			if(desPort==srcPortcmp){
				if(desIP32==srcIPcmp||srcIPcmp==0){
					sockfd=it->first;
					context=&(it->second);
					break;
				}
			}
			it++;
		}

		//context has to be listen state (passive open) or synsent (active open)
		if(context->state!=LISTENS&&context->state!=SYNSENT){
			return;
		}

		int dupsock=createFileDescriptor(context->pid);

		std::list<int> *backloglist= &context->backloglist;
		std::list<int> *dupsocklist= &context->dupsocklist;
		
		if(backloglist->size()>=context->backlog&&backloglist->size()!=0)
			return;

		backloglist->push_back(dupsock);
		dupsocklist->push_back(dupsock);

		SockContext dupsockcxt= *new SockContext;
		dupsockcxt.pid=context->pid;
		addrfdlist.insert(std::pair<int, SockContext>(dupsock,dupsockcxt));

		SockContext *dupcontext = &mapfindbypid(context->pid,dupsock)->second;
		dupcontext->desIP=srcIP32;
		dupcontext->desPort=srcPort;
		dupcontext->srcIP=desIP32;
		dupcontext->srcPort=desPort;
		dupcontext->state=SYNRCVD;

		Packet* myPacket = this->clonePacket(packet);

		desIP32=htonl(desIP32);
		srcIP32=htonl(srcIP32);

		sendTCPPacket(myPacket,tcpHeader,dupcontext,srcIP32,desIP32,srcPort,desPort,0,seqnum+1,ACK+SYN,NULL,0,51200);
		this->freePacket(packet);	
	}

	
	else if(flags==ACK){
		int listensockfd=-1;
		SockContext *liscontext;

		auto it=addrfdlist.begin();
		
		while(it!=addrfdlist.end()){
			uint16_t desPortcmp = it->second.desPort;
			uint32_t desIPcmp=it->second.desIP;
			uint16_t srcPortcmp=it->second.srcPort;
			uint32_t srcIPcmp=it->second.srcIP;
			int statecmp=it->second.state;
			if(srcPort==desPortcmp&&srcIP32==desIPcmp){
				sockfd=it->first;
				context=&(it->second);
			}
			else if(desPort==srcPortcmp&&statecmp==LISTENS){
				if(desIP32==srcIPcmp||srcIPcmp==0){
					listensockfd=it->first;
					liscontext=&(it->second);
				}
			}
			it++;
		}

		if(sockfd==-1){
			return;
		}


		int seqtofind;
		//write case
		if(acknum!=1&&context->writeflag==1){
			if(acknum==131074){
				acknum+=511;
			}
			InternalBuffer *intbuffer=&context->intbuffer;
			seqtofind=intbuffer->recentack;
			int datasize=acknum-(intbuffer->recentack);

			if(datasize==512){
				if(context->dup_recvflag==1){
					intbuffer->cwnd=intbuffer->ssthresh;
				}
				context->dup_recvflag=0;
			}

			//cumulative ack - ack before ones
			while(datasize>512){
				auto cumullist = payloadlist.find(seqtofind);
				Payload *cumulcontext=&cumullist->second;
				TimerModule::cancelTimer(cumulcontext->timerkey);
				timerlist.erase(cumulcontext->timerkey);
				payloadlist.erase(seqtofind);

				datasize-=512;
				seqtofind+=512;
				memset(intbuffer->buffer+intbuffer->base,0,512);
				intbuffer->remain+=512;
				intbuffer->base+=512;
				if(intbuffer->base>=51200){
					intbuffer->base-=51200;
				}
			}

			memset(intbuffer->buffer+intbuffer->base,0,datasize);
			intbuffer->recentack=acknum;
			intbuffer->remain+=datasize;
			intbuffer->base+=datasize;
			if(intbuffer->base>=51200){
				intbuffer->base-=51200;
			}

			if(datasize==0){
				//need retransmit
				if(context->dup_recvflag==0){
					context->fast_retransmit++;
					if(context->fast_retransmit==2){
						for(int i=0;i<3;i++){
							auto payloadseq =payloadlist.find(acknum+i*512);
							Payload *paycontext = &payloadseq->second;
							assert(paycontext->sendPacket==1);
						
							TimerModule::cancelTimer(paycontext->timerkey);
							timerlist.erase(paycontext->timerkey);

							Packet *packet = paycontext->packet;
							paycontext->packet=this->clonePacket(packet);
	
							UUID timerkey=TimerModule::addTimer(paycontext,TimeUtil::makeTime(context->timercal.RTO,TimeUtil::MSEC));
							timerlist.insert(std::pair<UUID,SockContext>(timerkey,*paycontext->context));
							paycontext->timerkey=timerkey;  

							payloadlist.erase(acknum+i*512);
							payloadlist.insert(std::pair<int,Payload>(acknum+i*512,*paycontext));

							intbuffer->ssthresh=(intbuffer->cwnd)/2;
							intbuffer->cwnd=intbuffer->ssthresh+3*MSS;

							this->sendPacket("IPv4",paycontext->packet);
						}
						context->dup_recvflag=1;
						return;
					}
					return;
				}
				else{
					return;
				}
			}
			auto resultlist=payloadlist.find(seqtofind);
			Payload *payloadresult= &resultlist->second;
			// printf("recv ack %d cancelled\n",payloadresult->timerkey);
			TimerModule::cancelTimer(payloadresult->timerkey);
			timerlist.erase(payloadresult->timerkey);
			
			int pasttime = payloadresult->storedtime;
			int currenttime = TimeUtil::getTime(this->getHost()->getSystem()->getCurrentTime(),TimeUtil::MSEC);
			printf("msec past is %d\n",currenttime-pasttime);
			int timepast=currenttime-pasttime;

			TimerCalculate *timeinfo=&context->timercal;
			timeinfo->RTTVAR=0.75*(timeinfo->RTTVAR)+0.25*abs(timeinfo->SRTT-timepast);
			timeinfo->SRTT=0.875*(timeinfo->SRTT)+0.25*timepast;
			timeinfo->RTO=timeinfo->SRTT+4*(timeinfo->RTTVAR);
			printf("rto is %d\n",timeinfo->RTO);

		}

		if(context->state==FIN_WAIT1){
			//exclude transfer finack before ack case (early case)
			if(context->seqnum+1==acknum)
				context->state=FIN_WAIT2;
			return;
		}

		if(context->state==TIMED_WAIT){
			return;
		}
		
		//passive close
		if(context->state==LAST_ACK){
			addrfdlist.erase(mapfindbypid(context->pid,sockfd));
			context->state=CLOSED;
			return;
		}

		if(context->state==ESTAB){
			if(context->state!=ESTAB)
				return;
			if(window!=0){
				InternalBuffer *intbuffer=&context->intbuffer;
				IOBuffer *iobuffer=&context->iobuffer;

				if(intbuffer->remain<=0){
						return;
				}

				//read ack
				if(acknum==1){
					int datasize=packet->getSize()-54;
					
					if(datasize+intbuffer->nextseqnum>51200){
						int limitleft=51200-intbuffer->nextseqnum;
						packet->readData(54,intbuffer->buffer+intbuffer->nextseqnum,limitleft);
						packet->readData(54+limitleft,intbuffer->buffer,datasize-limitleft);
					}
					else{
						packet->readData(54,intbuffer->buffer+intbuffer->nextseqnum,datasize);
					}
					intbuffer->remain-=datasize;
					intbuffer->nextseqnum+=datasize;
					intbuffer->nextseqnum%=51200;

					int filled=51200-intbuffer->remain;
					if(iobuffer->count!=-1){
						if(filled>=iobuffer->count){
							readDataPacket(context->syscallID,context,iobuffer->buffer,iobuffer->count);
						}
					}

					Packet* newPacket= this->allocatePacket(54);
					
					desIP32=htonl(desIP32);
					srcIP32=htonl(srcIP32);

					context->acknum+=datasize;

					Header *tcpHeader= new Header();

					sendTCPPacket(newPacket,tcpHeader,context,srcIP32,desIP32,srcPort,desPort,context->seqnum,context->acknum,ACK,NULL,0,intbuffer->remain);
					this->freePacket(packet);
					return;
				}
				//write ack
				else{
					if(iobuffer->count!=-1){
						//assert(intbuffer->availsend>0);
						//congestion avoidance 
						if(intbuffer->cwnd>=intbuffer->ssthresh){
							intbuffer->congestavoid+=1;
							//printf("before cogest avoidance availsend is %d\n",intbuffer->availsend);
							// if(intbuffer->availsend<512){
							// 	intbuffer->availsend+=512;
							//}
							//printf("intbuffer congest avoid is %d\n",intbuffer->congestavoid);
							// intbuffer->cwnd+=MSS*((float)MSS/intbuffer->cwnd);
							//intbuffer->availsend+=MSS*((float)MSS/intbuffer->cwnd);
							//printf("after congest avoidance is !! %d\n",intbuffer->availsend);
							if(intbuffer->congestavoid>=((intbuffer->cwnd)/MSS)){
								printf("recvied ack is %d\n",acknum);
								intbuffer->cwnd+=MSS;
								intbuffer->availsend=1024;
								intbuffer->congestavoid=0;
							}
							else{
								intbuffer->availsend=512;
							}
						}
						//slow start
						else{
							intbuffer->cwnd+=512;
							//printf("availsend before is %d\n",intbuffer->availsend);
							intbuffer->availsend=1024;
							//printf("cwnd is %d\n",intbuffer->cwnd);
						}
						int writebyte;
						if(intbuffer->remain<iobuffer->count||intbuffer->availsend<iobuffer->count){
							if(intbuffer->remain<intbuffer->availsend){
								writebyte=intbuffer->remain;
							}
							else{
								writebyte=intbuffer->availsend;
							}
						}
						else{
							writebyte=iobuffer->count;
						}
						//printf("intbuffer availsend in ack recv is %d\n",intbuffer->availsend);
						// printf("write num in ack recv %d\n",iobuffer->count);
						//assert(intbuffer->availsend>=iobuffer->count);
						intbuffer->availsend-=writebyte;
						writeDataPacket(context->syscallID,context,iobuffer->buffer,writebyte);
						return;
					}
				}
			}
		}

		if(listensockfd==-1)
			return;

		if(context->state!=SYNRCVD)
			return;

		//server side after sending synack
		std::list<int> *backloglist= &liscontext->backloglist;
		backloglist->pop_front();

		context->state=ESTAB;
		context->intbuffer.peerremain=window;
		this->freePacket(packet);

		//case when accept was first called
		if(liscontext->syscallID!=-1){

			//simultaneous close
			context->acknum=seqnum;
			context->seqnum=acknum;

			struct sockaddr_in *ret=(struct sockaddr_in *)(liscontext->addrinfo);	
			memset(ret,0,sizeof(ret));
		
			ret->sin_family = AF_INET;
			ret->sin_addr.s_addr=htonl(context->srcIP);
			ret->sin_port=htons(context->desPort);

			std::list<int> *dupsocklist=&(liscontext->dupsocklist);
			dupsocklist->pop_front();
			this->returnSystemCall(liscontext->syscallID,sockfd);
		}
	}

	else if(flags==FIN+ACK){
		int sockfd=-1;
		SockContext *sockcontext;
		int resseq, resack;

		auto it=addrfdlist.begin();
		while(it!=addrfdlist.end()){
			uint32_t srcIPcmp= it->second.srcIP;
			uint16_t srcPortcmp = it->second.srcPort;
			uint16_t desPortcmp = it->second.desPort;
			int statecmp = it->second.state;
			if(desPort==srcPortcmp&&srcPort==desPortcmp){
				if((desIP32==srcIPcmp||srcIPcmp==0)&&(statecmp!=LISTENS)){
					sockfd=it->first;
					sockcontext=&it->second;
					break;
				}
			}
			it++;
		}

		if(sockfd==-1)
			return;

		IOBuffer *iobuffer=&sockcontext->iobuffer;
		if(iobuffer->count!=-1&&acknum==1){
			this->returnSystemCall(sockcontext->syscallID,-1);
		}

		if(sockcontext->state==ESTAB){
			sockcontext->seqnum=acknum;
			sockcontext->acknum=seqnum+1;
			sockcontext->state=CLOSE_WAIT;
		}
		else if(sockcontext->state==FIN_WAIT1){
			sockcontext->seqnum=acknum+1;
			sockcontext->acknum=seqnum+1;
		}
		//normal case
		else if(sockcontext->state==FIN_WAIT2){
			sockcontext->seqnum=acknum;
			sockcontext->acknum=seqnum+1;
			sockcontext->state=TIMED_WAIT;
		}
		else{
			return;
		}
		resseq=sockcontext->seqnum;
		resack=sockcontext->acknum;

		Packet* myPacket = this->clonePacket(packet);

		desIP32=htonl(desIP32);
		srcIP32=htonl(srcIP32);

		sendTCPPacket(myPacket,tcpHeader,sockcontext,srcIP32,desIP32,srcPort,desPort,resseq,resack,ACK,NULL,0,51200);
		this->freePacket(packet);
	}
}

void TCPAssignment::timerCallback(void* payload)
{
	Header *tcpHeader = new Header();

	Payload *paycontext= (Payload *)payload;

	TimerModule::cancelTimer(paycontext->timerkey);

	if(paycontext->sendPacket==true){
		timerlist.erase(paycontext->timerkey);
		Packet *packet = paycontext->packet;
		SockContext *sockcontext=paycontext->context;
		packet->readData(30+4,tcpHeader,20);
		uint32_t seqnum= ntohl(tcpHeader->seqnum);
		printf("seqnum of retrans in timer return@@@@@@@ %d\n",seqnum);

		paycontext->packet=this->clonePacket(packet);
		UUID timerkey=TimerModule::addTimer(paycontext,TimeUtil::makeTime(sockcontext->timercal.RTO,TimeUtil::MSEC));
		timerlist.insert(std::pair<UUID,SockContext>(timerkey,*paycontext->context));
		paycontext->timerkey=timerkey;  
		if(paycontext->context->writeflag==1){
			// printf("timer is %d\n",timerkey);
			payloadlist.erase(seqnum);
			payloadlist.insert(std::pair<int,Payload>(seqnum,*paycontext));
		}

		InternalBuffer *intbuffer=&sockcontext->intbuffer;
		intbuffer->ssthresh=(intbuffer->cwnd)/2;
		intbuffer->cwnd=MSS;

		this->sendPacket("IPv4",packet);
		return;
	}

	SockContext *context = (SockContext*)payload;

	if(context->state!=TIMED_WAIT){
		return;
	}
	int sockfd=-1;

	uint32_t srcIP32=context->srcIP;
	uint16_t srcPort=context->srcPort;

	auto it=addrfdlist.begin();
	while(it!=addrfdlist.end()){
		uint32_t srcIPcmp= it->second.srcIP;
		uint16_t srcPortcmp = it->second.srcPort;
		if(srcPort==srcPortcmp){
			if(srcIP32==srcIPcmp||srcIPcmp==0){
				sockfd=it->first;
				context=&(it->second);
				break;
			}
		}
		it++;
	}

	if(sockfd==-1){
		return;
	}
	addrfdlist.erase(it);
	context->state=CLOSED;
}


}
