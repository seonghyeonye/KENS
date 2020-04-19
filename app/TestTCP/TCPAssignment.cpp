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
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
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

void TCPAssignment::sendTCPPacket(Packet *packet,Header *tcpHeader, uint32_t desIP32, uint32_t srcIP32, uint16_t desPort, uint16_t srcPort, uint32_t seqnum, uint32_t acknum, uint8_t flags){
	packet->writeData(14+12,&srcIP32,4);
	packet->writeData(14+16,&desIP32,4);
	
	tcpHeader->srcPort=htons(srcPort);
	tcpHeader->desPort=htons(desPort);
	tcpHeader->seqnum=htonl(seqnum);
	tcpHeader->acknum=htonl(acknum);
	tcpHeader->len=(5<<4);
	tcpHeader->flags=flags;
	tcpHeader->urg_ptr=0;
	tcpHeader->checksum=0;
	tcpHeader->checksum = htons(~(NetworkUtil::tcp_sum(srcIP32, desIP32, (uint8_t*)tcpHeader, 20)));

	packet->writeData(30+4,tcpHeader,20);

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
	if(context->srcIP!=-1&&context->state!=LISTENS){
		printf("close seqnum is %d",context->seqnum);
		printf("close acknum is %d\n",context->acknum);
	
		desIP32=context->desIP;
		desPort=context->desPort;
		srcIP32=context->srcIP;
		srcPort=context->srcPort;

		desIP32=htonl(desIP32);
		srcIP32=htonl(srcIP32);

		Packet* newPacket= this->allocatePacket(54);

		Header *tcpHeader = new Header();
		sendTCPPacket(newPacket,tcpHeader,desIP32,srcIP32,desPort,srcPort,context->seqnum,context->acknum,FIN+ACK);

		context->state=FIN_WAIT1;
		context->syscallID=syscallUUID;

		//to store context after close
		closelist.insert(std::pair<int,SockContext>(fd,*context));
	}
	addrfdlist.erase(mapfindbypid(pid,fd));
	this->removeFileDescriptor(pid,fd);
	this->returnSystemCall(syscallUUID,0);
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

	sendTCPPacket(newPacket,tcpHeader,desIP32,srcIP32,desPort,srcPort,context->seqnum,context->acknum,SYN);
	context->state=SYNSENT;
	context->syscallID=syscallUUID;
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog){
	SockContext *context= &mapfindbypid(pid,sockfd)->second;
	//not bound connection
	if(context->srcIP==-1||context->srcPort==-1){
		this->returnSystemCall(syscallUUID,-1);
	}
	
	context->backlog=backlog;
	context->state=LISTENS;
	this->returnSystemCall(syscallUUID,0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	printf("accept\n");
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
			dupcontext->state=ESTAB;
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
	uint16_t checksum;
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

	//uint16_t val=NetworkUtil::tcp_sum(desIP32, srcIP32, (uint8_t*)tcpHeader, 20)));
	// printf("val of checksum is %d\n",val);

	//client case connect
	if(flags==SYN+ACK){
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

		//synnum of client past and acknum of sender -1 has to be equal
		//checksum check REEEEEEEEEEEE!
		printf("acknum in synack is %d\n",acknum);
		printf("seqnum in synack is %d\n",seqnum);

		context->seqnum=acknum;
		context->acknum=seqnum+1;

		Packet* myPacket = this->clonePacket(packet);

		desIP32=htonl(desIP32);
		srcIP32=htonl(srcIP32);

		sendTCPPacket(myPacket,tcpHeader,srcIP32,desIP32,srcPort,desPort,acknum,seqnum+1,ACK);

		//state change
		context->state=ESTAB;
		this->freePacket(packet);

		this->returnSystemCall(context->syscallID,0);
	}

	//server incoming client
	else if(flags==SYN){
		printf("syn enter\n");
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

		if(backloglist->size()>=context->backlog)
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

		sendTCPPacket(myPacket,tcpHeader,srcIP32,desIP32,srcPort,desPort,0,seqnum+1,ACK+SYN);

		//state change
		this->freePacket(packet);	
		printf("synack sent?\n");
	}

	
	else if(flags==ACK){
		printf("ack enter\n");
		int closesockfd=-1;
		int listensockfd=-1;
		SockContext *liscontext;
		SockContext *closecontext;

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
		printf("listensockfd is %d\n",listensockfd);
		printf("sockfd is %d\n",sockfd);

		if(sockfd==-1){
			//client side after close
			printf("closed?\n");
			auto it=closelist.begin();
			while(it!=closelist.end()){
				uint32_t srcIPcmp= it->second.srcIP;
				uint16_t srcPortcmp = it->second.srcPort;
				if(desPort==srcPortcmp){
					if(desIP32==srcIPcmp||srcIPcmp==0){
						closesockfd=it->first;
						closecontext=&(it->second);
						break;
					}
				}
				it++;
			}
			printf("close socket number is %d\n",closesockfd);
			if(closesockfd==-1)
				return;

			if(closecontext->state==FIN_WAIT1){
				printf("before cases\n");
				printf("seqnum for before is %d\n",seqnum);
				printf("acknum for before is %d\n",acknum);
				closecontext->state=FIN_WAIT2;
				return;
			}

			if(closecontext->state==TIMED_WAIT){
				printf("seqnum for after is %d\n",seqnum);
				printf("acknum for after is %d\n",acknum);
				printf("after cases\n");
				return;
			}
			
		}
		printf("state is %d\n",context->state);

		if(listensockfd==-1)
			return;

		//server side last ack receive ack
		if(context->state==LAST_ACK){
			context->state=CLOSED;
			return;
		}

		if(context->state!=SYNRCVD)
			return;

		//server side after sending synack
		std::list<int> *backloglist= &liscontext->backloglist;
		backloglist->pop_front();

		context->state=ESTAB;
		printf("fd is right after estab is %d\n",sockfd);
		this->freePacket(packet);

		//case when accept was first called
		if(liscontext->syscallID!=-1){
			printf("accept before!!!\n");

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
		int closesockfd=-1;
		SockContext *closecontext;
		int sockfd=-1;
		SockContext *sockcontext;
		int resseq, resack;
		
		//client case 
		auto it=closelist.begin();
		while(it!=closelist.end()){
			uint32_t srcIPcmp= it->second.srcIP;
			uint16_t srcPortcmp = it->second.srcPort;
			if(desPort==srcPortcmp){
				if(desIP32==srcIPcmp||srcIPcmp==0){
					closesockfd=it->first;
					closecontext=&(it->second);
					break;
				}
			}
			it++;
		}

		if(closesockfd==-1){
			//server case
			auto it=addrfdlist.begin();
			while(it!=addrfdlist.end()){
				uint32_t srcIPcmp= it->second.srcIP;
				uint16_t srcPortcmp = it->second.srcPort;
				int statecmp = it->second.state;
				if(desPort==srcPortcmp){
					if(desIP32==srcIPcmp||srcIPcmp==0&&(statecmp!=LISTENS)){
						sockfd=it->first;
						sockcontext=&it->second;
						break;
					}
				}
				it++;
			}

			if(sockfd==-1||sockcontext->state!=ESTAB)
				return;

			printf("state is %d\n",sockcontext->state);

			printf("estab\n");
			sockcontext->seqnum=acknum;
			sockcontext->acknum=seqnum+1;
			resseq=sockcontext->seqnum;
			resack=sockcontext->acknum;
			sockcontext->state=CLOSE_WAIT;
		}
		//printf("finack!!\n");

		//client side
		else{

			//simulataneous close 
			if(closecontext->state==FIN_WAIT1){
				closecontext->seqnum=acknum+1;
				closecontext->acknum=seqnum+1;
			}
			else if(closecontext->state==FIN_WAIT2){
				closecontext->seqnum=acknum;
				closecontext->acknum=seqnum+1;
			}
			else{
				return;
			}
			resseq=closecontext->seqnum;
			resack=closecontext->acknum;
			closecontext->state=TIMED_WAIT;
		}
			
		//printf("state is %d\n",closecontext->state);
			//return;

		//printf("closesockfd is %d\n",closesockfd);
		printf("seqnum is %d\n",resseq);
		printf("acknum is %d\n",resack);

		Packet* myPacket = this->clonePacket(packet);
		Packet* myPacket2 = this->clonePacket(packet);

		desIP32=htonl(desIP32);
		srcIP32=htonl(srcIP32);

		sendTCPPacket(myPacket,tcpHeader,srcIP32,desIP32,srcPort,desPort,resseq,resack,ACK);

		printf("end of rece finack\n");

		//only for client case - last wait for 2min
		if(closesockfd!=-1)
			TimerModule::addTimer(closecontext,TimeUtil::makeTime(120,TimeUtil::SEC));
		this->freePacket(packet);
	}
}

void TCPAssignment::timerCallback(void* payload)
{
	SockContext *closecontext = (SockContext*)payload;

	if(closecontext->state!=TIMED_WAIT){
		return;
	}
	
	printf("closecontext pid is %d\n",closecontext->pid);

	int closesockfd=-1;

	uint32_t srcIP32=closecontext->srcIP;
	uint16_t srcPort=closecontext->srcPort;

	auto it=closelist.begin();
	while(it!=closelist.end()){
		uint32_t srcIPcmp= it->second.srcIP;
		uint16_t srcPortcmp = it->second.srcPort;
		if(srcPort==srcPortcmp){
			if(srcIP32==srcIPcmp||srcIPcmp==0){
				closesockfd=it->first;
				closecontext=&(it->second);
				break;
			}
		}
		it++;
	}

	if(closesockfd==-1){
		//printf("error\n");
		return;
	}
	printf("closesockfd is %d\n",closesockfd);
	closelist.erase(it);

	closecontext->state=CLOSED;
}


}
