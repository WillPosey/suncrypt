#include "SuncryptSocket.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <iostream>
#include <cstring>
#include <algorithm>

using std::string;
using std::cout;
using std::endl;
using std::copy;

/***********************************************************************************
 *
 **********************************************************************************/
SuncryptSocket::SuncryptSocket(const string portNum)
{	
	struct addrinfo hints, *addrInfo, *p;
	recvBufferGood = false;
	socketGood = false;
	recvBufferLength = 0;
	port = portNum;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	cout << "PORT: " << port.c_str() << endl;

	if (getaddrinfo(NULL, port.c_str(), &hints, &addrInfo) != 0) 
	{
		cout << "Error in SuncryptSocket Constructor: getaddrinfo()" << endl;
		return;
	}

	// loop through all the results and bind to the first we can
	for(p = addrInfo; p != NULL; p = p->ai_next) 
	{
		if ((sockFd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) 
			continue;
		if (bind(sockFd, p->ai_addr, p->ai_addrlen) == -1) 
		{
			close(sockFd);
			cout << "Error in SuncryptSocket Constructor: bind()" << endl;
			perror("Errno Message");
			continue;
		}
		break;
	}

	if (p == NULL)
		cout << "Error in SuncryptSocket Constructor: failed to bind" << endl;
	else
	{
		freeaddrinfo(addrInfo);
		socketGood = true;
	}
	
}

/***********************************************************************************
 *
 **********************************************************************************/
SuncryptSocket::~SuncryptSocket()
{
	if(socketGood)
		close(sockFd);
}

/***********************************************************************************
 *
 **********************************************************************************/
int SuncryptSocket::Send(const string destIP, const char* msg, size_t msgLength)
{
	if(!socketGood)
		return -1;

	int numBlks;
	msgHeader_t msgHeader, recvMsgHeader;
	char blk[BLK_SIZE];
	struct sockaddr_in sendAddr, recvAddr;
	socklen_t sendAddrLen, recvAddrLen;
	char str[INET_ADDRSTRLEN];

	memset(&sendAddr, 0, sizeof(sendAddr));
	sendAddr.sin_family = AF_INET;
	sendAddr.sin_port = htons(atoi(port.c_str()));
	inet_pton(AF_INET, destIP.c_str(), &(sendAddr.sin_addr));

	numBlks = msgLength / MAX_MSG_SIZE;
	if(msgLength%MAX_MSG_SIZE)
		numBlks++;

	cout << endl << "NUM BLKS: " << numBlks << endl;

	msgHeader.finalBlk = 0;
	msgHeader.seqNum = 0;
	msgHeader.msgSize = MAX_MSG_SIZE;

	for(int i=0; i<numBlks; i++)
	{
		memset(blk, 0, MAX_MSG_SIZE);
		if(i==(numBlks-1))
		{
			msgHeader.msgSize = msgLength%MAX_MSG_SIZE;
			msgHeader.finalBlk = 1;
		}
		memcpy(blk, &msgHeader, sizeof(msgHeader));
		memcpy(blk, msg+(i*MAX_MSG_SIZE), msgHeader.msgSize);


		cout << endl << "Sending: total=" << msgHeader.msgSize+sizeof(msgHeader) << " msgSize=" << msgHeader.msgSize << " and msgHeaderSize=" << sizeof(msgHeader) << endl;
		inet_ntop(AF_INET, &(sendAddr.sin_addr), str, INET_ADDRSTRLEN);
		cout << "Sending to " << str << " on port " << sendAddr.sin_port << endl << endl; 

		if(sendto(sockFd, blk, msgHeader.msgSize+sizeof(msgHeader), 0, (struct sockaddr*)&sendAddr, sizeof(sendAddr)) < 0)
		{
			cout << "Error: SuncryptSocket::Send()-->sendto()" << endl;
			perror("Errno Message");
			return -1;
		}
		/*
		do
		{
			if(recvfrom(sockFd, (char*)&recvMsgHeader, sizeof(recvMsgHeader), 0, (struct sockaddr*)&recvAddr, &recvAddrLen) < 0)
			{
				cout << "Error: SuncryptSocket::Send()-->recvfrom()" << endl;
				perror("Errno Message");
				return -1;
			}
			if(recvAddr.sin_addr.s_addr!=sendAddr.sin_addr.s_addr)
				recvMsgHeader.seqNum = msgHeader.seqNum-1;
		}while(recvMsgHeader.seqNum != msgHeader.seqNum);
		*/

		msgHeader.seqNum++;
	}
	return 0;
}

/***********************************************************************************
 *
 **********************************************************************************/
int SuncryptSocket::Receive()
{
	if(!socketGood)
		return -1;

	if(recvBufferGood)
	{
		recvBuffer.clear();
		recvBufferGood = false;
	}

	sockaddr_in senderAddr;
	uint32_t savedSenderAddr;
	bool firstRecv;
	socklen_t senderAddrLen;
	msgHeader_t msgHeader;
	ssize_t numBytes;
	char blk[BLK_SIZE];

	memset(&msgHeader, 0, sizeof(msgHeader));
	firstRecv = true;

	while(!msgHeader.finalBlk)
	{
		numBytes = recvfrom(sockFd, blk, BLK_SIZE, 0, (struct sockaddr*)&senderAddr, &senderAddrLen);
		if(numBytes < 0 || numBytes < sizeof(msgHeader))
		{
			cout << "Error: SuncryptSocket::Receive()-->recvfrom()" << endl;
			perror("Errno Message");
			return -1;
		}

		if(firstRecv)
		{
			savedSenderAddr = senderAddr.sin_addr.s_addr;
			firstRecv = false;
		}
		else if(savedSenderAddr != senderAddr.sin_addr.s_addr)
		{
			cout << "Error: SuncryptSocket::Receive()-->recvfrom() different address" << endl;
			return -1;
		}

		memcpy(&msgHeader, blk, sizeof(msgHeader));
		recvBuffer.insert(recvBuffer.end(), blk+sizeof(msgHeader), blk+sizeof(msgHeader)+msgHeader.msgSize);

		/*
		if(sendto(sockFd, &msgHeader, sizeof(msgHeader), 0, (struct sockaddr*)&senderAddr, senderAddrLen) < 0)
		{
			cout << "Error: SuncryptSocket::Send()-->sendto()" << endl;
			perror("Errno Message");
			return -1;
		}
		*/
	}

	recvBufferGood = true;
}

/***********************************************************************************
 *
 **********************************************************************************/
void SuncryptSocket::GetRecvMsg(char* buffer, size_t bufferLength)
{
	int length = (recvBufferLength > bufferLength) ? bufferLength : recvBufferLength;
	if(recvBufferGood)
		copy_n(recvBuffer.begin(), length, buffer);
}