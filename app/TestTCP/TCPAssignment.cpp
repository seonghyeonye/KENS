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
	int ret;
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

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type){
	if(domain!=PF_INET||type!=SOCK_STREAM)
		this->returnSystemCall(syscallUUID,-1);
	int fd=this->createFileDescriptor(pid);
	addrfdlist.insert(std::pair<int, SockContext>(fd,SockContext()));
	this->returnSystemCall(syscallUUID,fd);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd){
	addrfdlist.erase(fd);
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

	desIP32= ntohl((addr_int->sin_addr).s_addr);
	desIP[0]=desIP32>>24;
	desIP[1]=(u_char)(desIP32>>16);
	desIP[2]=(u_char)(desIP32>>8);
	desIP[3]=(u_char)desIP32;

	auto entry= addrfdlist.find(sockfd);

	//printf("des ip in connect is %d\n",desIP32);
	entry->second.desIP=desIP32;
	entry->second.desPort=desPort;

	tableidx= this->getHost()->getRoutingTable(desIP);

	if(entry->second.srcIP==-1&&entry->second.srcPort==-1){
		this->getHost()->getIPAddr(srcIP,tableidx);

		srcIP32=srcIP[0]<<24|srcIP[1]<<16|srcIP[2]<<8|srcIP[3];
		// Dynamic and/or Private Port : 49152 ~ 65535
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
			//printf("tempport is %d\n",tempport);
			break;
		}
	}
	else{
		srcIP32=entry->second.srcIP;
		srcPort=entry->second.srcPort;
	}



	entry->second.srcIP=srcIP32;
	entry->second.srcPort=srcPort;

	//printf("des ipaddr and port is %u.%u.%u.%u %d\n",desIP[0],desIP[1],desIP[2],desIP[3], desPort);
	//printf("src ipaddr and port is %u.%u.%u.%u %d\n",srcIP[0],srcIP[1],srcIP[2],srcIP[3],srcPort);

	entry->second.synbit=1;


	srcIP32=htonl(srcIP32);
	desIP32=htonl(desIP32);

	Packet* newPacket= this->allocatePacket(54);
	newPacket->writeData(14+12,&srcIP32,4);
	newPacket->writeData(14+16,&desIP32,4);

	Header *tcpHeader = new Header();
	tcpHeader->srcPort=htons(srcPort);
	tcpHeader->desPort=htons(desPort);
	tcpHeader->seqnum=0;
	tcpHeader->acknum=0;
	tcpHeader->len=(5<<4);
	tcpHeader->flags=SYN;
	tcpHeader->urg_ptr=0;
	tcpHeader->checksum=0;
	tcpHeader->checksum = htons(~(NetworkUtil::tcp_sum(srcIP32, desIP32, (uint8_t*)tcpHeader, 20)));

	//printf("checksum is %x\n",tcpHeader->checksum);
	//delete(tcpHeader);

	newPacket->writeData(30+4,tcpHeader,20);
//	this->sendPacket("IPv4",newPacket);

	// Packet* newPacket= NetworkModule::allocatePacket(sizeof(entry));
	// newPacket->writeData(0,&entry,sizeof(entry));
	// this->sendPacket("IPv4",newPacket);
	entry->second.state=SYNSENT;
	entry->second.syscallID=syscallUUID;

	this->sendPacket("IPv4",newPacket);

	uint32_t src, des;

	newPacket->readData(14+12,&src,4);
	newPacket->readData(14+16,&des,4);

	//printf("src and des is %d, %d\n",ntohl(src),ntohl(des));

	// srcIP32=ntohl(src);
	// desIP32=ntohl(des);

	// desIP[0]=desIP32>>24;
	// desIP[1]=(u_char)(desIP32>>16);
	// desIP[2]=(u_char)(desIP32>>8);
	// desIP[3]=(u_char)desIP32;

	// srcIP[0]=srcIP32>>24;
	// srcIP[1]=(u_char)(srcIP32>>16);
	// srcIP[2]=(u_char)(srcIP32>>8);
	// srcIP[3]=(u_char)srcIP32;

	// printf("des ipaddr and port in arriveis %u.%u.%u.%u %d\n",desIP[0],desIP[1],desIP[2],desIP[3], desPort);
	// printf("src ipaddr and port in arriveis %u.%u.%u.%u %d\n",srcIP[0],srcIP[1],srcIP[2],srcIP[3],srcPort);


}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog){
	printf("listen?");
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	printf("1111\n");
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen){
	const struct sockaddr_in *addr_int = (const struct sockaddr_in *)addr;
	unsigned short int portnum= ntohs(addr_int->sin_port);
	uint32_t ipaddr=ntohl((addr_int->sin_addr).s_addr);
	//std::cout<<"port original is "<<addr_int->sin_port<<std::endl;
	//std::cout<<"address and port is "<<pairval<<std::endl;
	auto it=addrfdlist.begin();

	while(it!=addrfdlist.end()){
		int fdcmp = it->first;
		int ipcmp = it->second.srcIP;
		int portcmp = it->second.srcPort;
		//std::cout<<"ipcmp is "<<ipcmp<<std::endl;
		//std::cout<<"portcmp is "<<portcmp<<std::endl;
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
			else{
				auto entry= addrfdlist.find(sockfd);
				entry->second.srcIP=ipaddr;
				entry->second.srcPort=portnum;
			}
		}
			
		it++;
	}
	this->returnSystemCall(syscallUUID,0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	auto entry= addrfdlist.find(sockfd);

	// if(addrinfo.compare("-1")==0)
	// 	return -1;

	uint32_t ipaddr= entry->second.srcIP;
	unsigned short int portnum = entry->second.srcPort;
	struct sockaddr_in *ret=(struct sockaddr_in *)addr;	

	memset(ret,0,sizeof(ret));
	
	ret->sin_family = AF_INET;
	ret->sin_addr.s_addr=htonl(ipaddr);
	ret->sin_port=htons(portnum);

	this->returnSystemCall(syscallUUID,0);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	auto entry= addrfdlist.find(sockfd);
	
	//printf("sockfd in getpeername is %d\n",sockfd);
	uint32_t ipaddr= entry->second.desIP;
	
	unsigned short int portnum = entry->second.desPort;
	struct sockaddr_in *ret=(struct sockaddr_in *)addr;	

	//printf("ipaddr in peername is %d\n",ipaddr);

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
	int sockfd=-1;

	packet->readData(14+12,&srcIP32,4);
	packet->readData(14+16,&desIP32,4);

	srcIP32=ntohl(srcIP32);
	desIP32=ntohl(desIP32);

	// desIP[0]=desIP32>>24;
	// desIP[1]=(u_char)(desIP32>>16);
	// desIP[2]=(u_char)(desIP32>>8);
	// desIP[3]=(u_char)desIP32;

	// srcIP[0]=srcIP32>>24;
	// srcIP[1]=(u_char)(srcIP32>>16);
	// srcIP[2]=(u_char)(srcIP32>>8);
	// srcIP[3]=(u_char)srcIP32;


	Header *tcpHeader = new Header();
	packet->readData(30+4, tcpHeader,20);

	srcPort=ntohs(tcpHeader->srcPort);
	desPort=ntohs(tcpHeader->desPort);
	flags = tcpHeader->flags;
	seqnum=ntohl(tcpHeader->seqnum);
	acknum=ntohl(tcpHeader->acknum);


	//  printf("des ipaddr and port in arriveis %u.%u.%u.%u %d\n",desIP[0],desIP[1],desIP[2],desIP[3], desPort);
	//  printf("src ipaddr and port in arriveis %u.%u.%u.%u %d\n",srcIP[0],srcIP[1],srcIP[2],srcIP[3],srcPort);
	if(flags==SYN+ACK){
		auto it=addrfdlist.begin();

		//printf("memeber num is %d\n",addrfdlist.size());

		while(it!=addrfdlist.end()){
			uint32_t srcIPcmp = it->second.srcIP;
			uint16_t srcPortcmp = it->second.srcPort;
			uint32_t desIPcmp = it->second.desIP;
			uint16_t desPortcmp = it->second.desPort;

			//printf("desPortcmp is %d\n",desPortcmp);

			if(desPortcmp==srcPort&&desIP32==srcIPcmp){
				sockfd=it->first;
				//printf("sockfd is %d\n",sockfd);
				break;
			}
		}

		// if(sockfd==-1){
		// 	printf("error");
		// }

		// printf("passssss here");

		SockContext *context = &(addrfdlist.find(sockfd)->second);


		if(flags&SYN==0||flags&ACK==0){
			printf("error!");
		}
		//synnum of client past and acknum of sender -1 has to be equal
		//checksum check

		Packet* myPacket = this->clonePacket(packet);

		desIP32=htonl(desIP32);
		srcIP32=htonl(srcIP32);

		myPacket->writeData(14+12,&desIP32,4);
		myPacket->writeData(14+16,&srcIP32,4);

		tcpHeader->srcPort=htons(desPort);
		tcpHeader->desPort=htons(srcPort);
		tcpHeader->flags=ACK;
		tcpHeader->seqnum=htonl(acknum);
		tcpHeader->acknum=htonl(seqnum+1);
		tcpHeader->checksum=0;
		tcpHeader->checksum= htons(~(NetworkUtil::tcp_sum(desIP32, srcIP32, (uint8_t*)tcpHeader, 20)));

		//printf("srcport client port should be 46218 %d\n",ntohs(tcpHeader->srcPort));
		myPacket->writeData(30+4, tcpHeader,20);

		//state change
		context->state=ESTAB;
		this->sendPacket("IPv4",myPacket);
		this->freePacket(packet);

		Header *header = new Header();
		myPacket->readData(30+4,header,20);
		// printf("header flag is %d\n",header->flags);
		// printf("header seqnum is %d\n",ntohl(tcpHeader->seqnum));
		// printf("header acknum is %d\n",ntohl(tcpHeader->acknum));
		// printf("seqnum given is %d\n",seqnum);
		// printf("header srcPort is %d\n",ntohs(tcpHeader->srcPort));
		// printf("header desPort is %d\n",ntohs(tcpHeader->desPort));


		this->returnSystemCall(context->syscallID,0);
	}
}

void TCPAssignment::timerCallback(void* payload)
{

}


}
