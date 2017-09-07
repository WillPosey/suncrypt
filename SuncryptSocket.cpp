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
	char sendHeader[HEADER_SIZE];

	memset(&sendAddr, 0, sizeof(sendAddr));
	sendAddr.sin_family = AF_INET;
	sendAddr.sin_port = htons(atoi(port.c_str()));
	inet_pton(AF_INET, destIP.c_str(), &(sendAddr.sin_addr));

	numBlks = msgLength / MAX_MSG_SIZE;
	if(msgLength%MAX_MSG_SIZE)
		numBlks++;

	cout << endl << "NUM BLKS: " << numBlks << endl;

	memset(&msgHeader, 0, sizeof(msgHeader));
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

		PackHeader(blk, msgHeader);
		memcpy(blk+HEADER_SIZE, msg+(i*MAX_MSG_SIZE), msgHeader.msgSize);

		cout << endl << "Sending: total=" << msgHeader.msgSize+HEADER_SIZE << " msgSize=" << msgHeader.msgSize << " and msgHeaderSize=" << HEADER_SIZE << endl;

		if(sendto(sockFd, blk, msgHeader.msgSize+HEADER_SIZE, 0, (struct sockaddr*)&sendAddr, sizeof(sendAddr)) < 0)
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
	socklen_t senderAddrLen = sizeof(senderAddr);
	char senderIP[INET_ADDRSTRLEN];
	string originalSenderIP;
	bool firstRecv;
	msgHeader_t msgHeader;
	ssize_t numBytes;
	char blk[BLK_SIZE];

	memset(&msgHeader, 0, sizeof(msgHeader));
	firstRecv = true;

	while(!msgHeader.finalBlk)
	{
		numBytes = recvfrom(sockFd, blk, BLK_SIZE, 0, (struct sockaddr*)&senderAddr, &senderAddrLen);
		if(numBytes < 0 || numBytes < HEADER_SIZE)
		{
			cout << "Error: SuncryptSocket::Receive()-->recvfrom()" << endl;
			perror("Errno Message");
			return -1;
		}

		inet_ntop(AF_INET, &(senderAddr.sin_addr), senderIP, INET_ADDRSTRLEN);
		if(firstRecv)
		{
			originalSenderIP = senderIP;
			firstRecv = false;
		}
		else if(originalSenderIP.compare(senderIP) != 0)
		{
			cout << "Error: SuncryptSocket::Receive()-->recvfrom() different IPs original=" << originalSenderIP << " last=" << senderIP << endl;
			return -1;
		}

		GetHeader(blk, &msgHeader);
		if(msgHeader.msgSize != (numBytes-HEADER_SIZE))
		{
			cout << "Error: SuncryptSocket::Receive()-->recvfrom() Partial Block Received" << endl;
			cout << "Message Size should have been " << msgHeader.msgSize+HEADER_SIZE << " but was " << numBytes << endl;
			return -1;
		}
		recvBuffer.insert(recvBuffer.end(), blk+HEADER_SIZE, blk+numBytes+1);

		/*
		if(sendto(sockFd, &msgHeader, HEADER_SIZE, 0, (struct sockaddr*)&senderAddr, senderAddrLen) < 0)
		{
			cout << "Error: SuncryptSocket::Send()-->sendto()" << endl;
			perror("Errno Message");
			return -1;
		}
		*/
	}

	recvBufferGood = true;
	return recvBuffer.size();
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

/***********************************************************************************
 *
 **********************************************************************************/
void SuncryptSocket::PackHeader(char* dest, msgHeader_t header)
{
	uint32_t seqNum_N = htonl(header.seqNum);
	uint16_t msgSize_N = htons(header.msgSize);
	uint16_t finalBlk_N = htons(header.finalBlk);

	int msgOffset = sizeof(seqNum_N);
	int finalOffset = msgOffset + sizeof(msgSize_N);

	memcpy(dest, &seqNum_N, sizeof(seqNum_N));
	cout << "seqNum in host order: " << header.seqNum << " seqNum in network order: " << seqNum_N << endl;
	memcpy(dest+msgOffset, &msgSize_N, sizeof(msgSize_N)); 
	cout << "msgSize in host order: " << header.msgSize << " msgSize in network order: " << msgSize_N << endl;
	memcpy(dest+finalOffset, &finalBlk_N, sizeof(finalBlk_N)); 
	cout << "finalBlk in host order: " << header.finalBlk << " finalBlk in network order: " << finalBlk_N << endl;

	printf("\n\n IN HEADER HEX: %08X %04X %04X\n\n", header.seqNum, header.msgSize, header.finalBlk);

	printf("\n\n IN BUFFER HEX: ");
	for(int i=0; i<HEADER_SIZE; i++)
		printf("%02X ", (unsigned char)dest[i]);
}

/***********************************************************************************
 *
 **********************************************************************************/
void SuncryptSocket::GetHeader(char* buffer, msgHeader_t *header)
{
	uint32_t seqNum_N;
	uint16_t msgSize_N;
	uint16_t finalBlk_N;

	int msgOffset = sizeof(seqNum_N);
	int finalOffset = msgOffset + sizeof(msgSize_N);

	memcpy(&seqNum_N, buffer, sizeof(seqNum_N));
	memcpy(&msgSize_N, buffer+msgOffset, sizeof(msgSize_N));
	memcpy(&finalBlk_N, buffer+finalOffset, sizeof(finalBlk_N));

	header->seqNum = ntohl(seqNum_N);
	header->msgSize = ntohs(msgSize_N);
	header->finalBlk = ntohs(finalBlk_N);
}