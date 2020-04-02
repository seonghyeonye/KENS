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
		ret=this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
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
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		ret=this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		ret=this->syscall_getsockname(syscallUUID, pid, param.param1_int,
			static_cast<struct sockaddr *>(param.param2_ptr),
			static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
	SystemCallInterface::returnSystemCall(syscallUUID,ret);
}

int TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type){
	if(domain!=PF_INET||type!=SOCK_STREAM)
		return -1;
	int fd=SystemCallInterface::createFileDescriptor(pid);
	addrfdlist.insert(std::pair<int,std::string>(fd,"-1"));
	return fd;

}

int TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd){
	addrfdlist.erase(fd);
	SystemCallInterface::removeFileDescriptor(pid,fd);
	return 0;
}

int TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen){
	const struct sockaddr_in *addr_int = (const struct sockaddr_in *)addr;
	unsigned short int port= ntohs(addr_int->sin_port);
	uint32_t hostaddr=(addr_int->sin_addr).s_addr;
	std::string ipaddr = std::to_string(hostaddr);
	std::string portnum = std::to_string(port);
	std::string pairval = ipaddr+":"+portnum;
	//std::cout<<"port original is "<<addr_int->sin_port<<std::endl;
	//std::cout<<"address and port is "<<pairval<<std::endl;
	auto it=addrfdlist.begin();

	while(it!=addrfdlist.end()){
		int fdcmp = it->first;
		std::string addrcmp = it->second;
		int delipos = addrcmp.find(":");
		std::string ipcmp = addrcmp.substr(0,delipos);
		std::string portcmp = addrcmp.substr(delipos+1);

		//std::cout<<"ipcmp is "<<ipcmp<<std::endl;
		//std::cout<<"portcmp is "<<portcmp<<std::endl;
		if(!portnum.compare(portcmp)){
			if(!ipaddr.compare(ipcmp))
				return -1;
			else if(hostaddr==INADDR_ANY||std::stoi(ipcmp)==INADDR_ANY)
				return -1;
		}
		else if(sockfd==fdcmp){
			if(ipcmp.compare("-1")!=0){
				return -1;
			}
			else{
				addrfdlist.find(sockfd)->second=pairval;
			}
		}
			
		it++;
	}
	return 0;
}

int TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	std::string addrinfo = addrfdlist.find(sockfd)->second;

	if(addrinfo.compare("-1")==0)
		return -1;

	int delipos=addrinfo.find(":");
	uint32_t ipaddr = stoi(addrinfo.substr(0,delipos));
	unsigned short int portnum = stoi(addrinfo.substr(delipos+1));
	struct sockaddr_in *ret=(struct sockaddr_in *)addr;	

	memset(ret,0,sizeof(ret));
	
	ret->sin_family = AF_INET;
	ret->sin_addr.s_addr=ipaddr;
	ret->sin_port=htons(portnum);

	return 0;
}
void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

}

void TCPAssignment::timerCallback(void* payload)
{

}


}
