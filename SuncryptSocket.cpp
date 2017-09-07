#include "SuncryptSocket.h"
#include <arpa/inet.h>
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
SuncryptSocket::SuncryptSocket(unsigned int portNum)
{
	recvBufferGood = false;
	socketGood = false;
	recvBufferLength = 0;

	port = portNum;

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));

	addr.sin_family = AF_INET;
	addr.sin_port = port;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	sockFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sockFd == -1)
	{
		cout << "Error in SuncryptSocket Constructor: socket()" << endl;
		perror("Errno Message");
	}
	else if(bind(sockFd, (struct sockaddr*)&addr, sizeof(addr)) == -1)
	{
		cout << "Error in SuncryptSocket Constructor: bind()" << endl;
		perror("Errno Message");
	}
	else
		socketGood = true;
}

/***********************************************************************************
 *
 **********************************************************************************/
SuncryptSocket::~SuncryptSocket()
{
	close(sockFd);
}

/***********************************************************************************
 *
 **********************************************************************************/
int SuncryptSocket::Send(const string destIP, const char* msg, size_t msgLength)
{
	int numBlks;
	msgHeader_t msgHeader, recvMsgHeader;
	char blk[BLK_SIZE];
	struct sockaddr_in sendAddr, recvAddr;
	socklen_t sendAddrLen, recvAddrLen;

	memset(&sendAddr, 0, sizeof(sendAddr));
	sendAddr.sin_family = AF_INET;
	sendAddr.sin_port = port;
	inet_pton(AF_INET, destIP.c_str(), &(sendAddr.sin_addr));

	numBlks = msgLength / MAX_MSG_SIZE;
	if(numBlks%MAX_MSG_SIZE || numBlks==0)
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
			msgHeader.msgSize = numBlks%MAX_MSG_SIZE;
			msgHeader.finalBlk = 1;
		}
		memcpy(blk, &msgHeader, sizeof(msgHeader));
		memcpy(blk, msg+(i*MAX_MSG_SIZE), msgHeader.msgSize);

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