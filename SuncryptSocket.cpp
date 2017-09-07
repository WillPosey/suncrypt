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
	char sendBlk[BLK_SIZE];
	char ack[HEADER_SIZE];
	struct sockaddr_in sendAddr, recvAddr;
	socklen_t sendAddrLen = sizeof(sendAddr);
	socklen_t recvAddrLen = sizeof(recvAddr);
	char recvIP[INET_ADDRSTRLEN];
	char sentIP[INET_ADDRSTRLEN];
	char sendHeader[HEADER_SIZE];

	memset(&sendAddr, 0, sizeof(sendAddr));
	sendAddr.sin_family = AF_INET;
	sendAddr.sin_port = htons(atoi(port.c_str()));
	inet_pton(AF_INET, destIP.c_str(), &(sendAddr.sin_addr));

	numBlks = msgLength / MAX_MSG_SIZE;
	if(msgLength%MAX_MSG_SIZE)
		numBlks++;

	memset(&msgHeader, 0, sizeof(msgHeader));
	msgHeader.finalBlk = 0;
	msgHeader.seqNum = 0;
	msgHeader.msgSize = MAX_MSG_SIZE;

	inet_ntop(AF_INET, &(sendAddr.sin_addr), sentIP, INET_ADDRSTRLEN);

	for(int i=0; i<numBlks; i++)
	{
		memset(sendBlk, 0, MAX_MSG_SIZE);
		if(i==(numBlks-1))
		{
			msgHeader.msgSize = msgLength%MAX_MSG_SIZE;
			msgHeader.finalBlk = 1;
		}

		PackHeader(sendBlk, msgHeader);
		memcpy(sendBlk+HEADER_SIZE, msg+(i*MAX_MSG_SIZE), msgHeader.msgSize);

		if(sendto(sockFd, sendBlk, msgHeader.msgSize+HEADER_SIZE, 0, (struct sockaddr*)&sendAddr, sendAddrLen) < 0)
		{
			cout << "Error: SuncryptSocket::Send()-->sendto()" << endl;
			perror("Errno Message");
			return -1;
		}
		
		do
		{
			if(recvfrom(sockFd, ack, HEADER_SIZE, 0, (struct sockaddr*)&recvAddr, &recvAddrLen) < 0)
			{
				cout << "Error: SuncryptSocket::Send()-->recvfrom() could not receive ack" << endl;
				perror("Errno Message");
				return -1;
			}

			inet_ntop(AF_INET, &(recvAddr.sin_addr), recvIP, INET_ADDRSTRLEN);
			if(string(sentIP).compare(recvIP) != 0)
				continue;
			GetHeader(ack, &recvMsgHeader);

		}while(recvMsgHeader.seqNum != msgHeader.seqNum);

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
	char ack[HEADER_SIZE];

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
		recvBuffer.insert(recvBuffer.end(), blk+HEADER_SIZE, blk+numBytes);
		recvBufferLength = recvBuffer.size();

		PackHeader(ack, msgHeader);
		if(sendto(sockFd, ack, HEADER_SIZE, 0, (struct sockaddr*)&senderAddr, senderAddrLen) < 0)
		{
			cout << "Error: SuncryptSocket::Receive()-->sendto() could not send ack" << endl;
			perror("Errno Message");
			return -1;
		}
		
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
	memcpy(dest+msgOffset, &msgSize_N, sizeof(msgSize_N)); 
	memcpy(dest+finalOffset, &finalBlk_N, sizeof(finalBlk_N)); 
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