/************************************************************************************************************
*	Author:			William Posey
*	Course: 		University of Florida, CNT 5410
*	Semester:		Fall 2017
*	Project:		Assignment 2, Suncrypt
*	File:			SuncryptSocket.cpp
*	Description:	This file contains definitions for methods of the SuncryptSocket class, which is used to
*					implement C UDP socket functionality
************************************************************************************************************/
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
#include <sys/time.h>

using std::string;
using std::cout;
using std::endl;
using std::copy;

/************************************************************************************************************
 *	@params:
 *				const string portNum: port number on which the socket should communicate through
 *	@return:
 *				n/a
 *	@desc:
 *				creates and binds a socket to any system IP address and the specified port
 ***********************************************************************************************************/
SuncryptSocket::SuncryptSocket(const string portNum)
{	
	struct addrinfo hints, *addrInfo, *p;
	recvBufferGood = false;
	socketGood = false;
	recvBufferLength = 0;
	port = portNum;

	/* set addrinfo values */
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	if (getaddrinfo(NULL, port.c_str(), &hints, &addrInfo) != 0) 
	{
		cout << "Error in SuncryptSocket Constructor: getaddrinfo()" << endl;
		return;
	}

	/* loop through until socket and bind calls are successful */
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

/************************************************************************************************************
 *	@params:
 *				n/a
 *	@return:
 *				n/a
 *	@desc:
 *				closes the socket
 ***********************************************************************************************************/
SuncryptSocket::~SuncryptSocket()
{
	if(socketGood)
		close(sockFd);
}

/************************************************************************************************************
 *	@params:
 *				const string destIP: desintation IP address (IPV4)
 *				const char* msg: buffer containing message to send
 *				size_t msgLength: length of message
 *	@return:
 *				0: succecss
 *				-1: error
 *	@desc:
 *				breaks the message into blocks, and sends one block at a time, waiting for an
 *				acknowledgement from the receiver for each block
 *				ignores any communication from IP not equivalent to receiver IP
 ***********************************************************************************************************/
int SuncryptSocket::Send(const string destIP, const char* msg, size_t msgLength)
{
	if(!socketGood)
		return -1;

	int numBlks;
	struct timeval ackTimeout;
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
	ackTimeout.tv_sec = 1;
	ackTimeout.tv_usec = 0;
	if(setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO,&ackTimeout,sizeof(ackTimeout)) < 0)
    {
		cout << "Error: SuncryptSocket::Send()-->setsockopt() could not set timeout" << endl;
		perror("Errno Message");
		return -1;
	}		

	for(int i=0; i<numBlks; i++)
	{
		do
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

			if(recvfrom(sockFd, ack, HEADER_SIZE, 0, (struct sockaddr*)&recvAddr, &recvAddrLen) < 0)
			{
				if(errno == EAGAIN || errno == EWOULDBLOCK)
					continue;
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

	ackTimeout.tv_sec = 0;
	ackTimeout.tv_usec = 0;
	if(setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO,&ackTimeout,sizeof(ackTimeout)) < 0)
    {
		cout << "Error: SuncryptSocket::Send()-->setsockopt() could not remove timeout" << endl;
		perror("Errno Message");
	}	

	return 0;
}

/************************************************************************************************************
 *	@params:
 *				n/a
 *	@return:
 *				-1: error
 *				otherwise: nmber of bytes received
 *	@desc:
 *				blocks and waits to receive an entire message, broken into blocks, into an internal buffer
 *				sends an ack for every block received, and receives blocks until final block flag set in
 *				the message header
 ***********************************************************************************************************/
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
	uint32_t nextSeqNum;

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

		GetHeader(blk, &msgHeader);
		if(msgHeader.msgSize != (numBytes-HEADER_SIZE))
		{
			cout << "Error: SuncryptSocket::Receive()-->recvfrom() Partial Block Received" << endl;
			cout << "Message Size should have been " << msgHeader.msgSize+HEADER_SIZE << " but was " << numBytes << endl;
			return -1;
		}

		inet_ntop(AF_INET, &(senderAddr.sin_addr), senderIP, INET_ADDRSTRLEN);
		if(firstRecv)
		{
			nextSeqNum = msgHeader.seqNum+1;
			originalSenderIP = senderIP;
			firstRecv = false;
			recvBuffer.insert(recvBuffer.end(), blk+HEADER_SIZE, blk+numBytes);
			recvBufferLength = recvBuffer.size();
		}
		else if(originalSenderIP.compare(senderIP) != 0)
		{
			cout << "Error: SuncryptSocket::Receive()-->recvfrom() different IPs original=" << originalSenderIP << " last=" << senderIP << endl;
			return -1;
		}
		else if(msgHeader.seqNum != nextSeqNum)
		{
			msgHeader.seqNum = nextSeqNum;
		}
		else
		{
			nextSeqNum = msgHeader.seqNum+1;
			recvBuffer.insert(recvBuffer.end(), blk+HEADER_SIZE, blk+numBytes);
			recvBufferLength = recvBuffer.size();
		}

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

/************************************************************************************************************
 *	@params:
 *				char* buffer: buffer to store received message
 *				size_t bufferLength: length of buffer
 *	@return:
 *				n/a
 *	@desc:
 *				copies the contents of the internal buffer containing the received message into the buffer
 ***********************************************************************************************************/
void SuncryptSocket::GetRecvMsg(char* buffer, size_t bufferLength)
{
	int length = (recvBufferLength > bufferLength) ? bufferLength : recvBufferLength;
	if(recvBufferGood)
		copy_n(recvBuffer.begin(), length, buffer);
}

/************************************************************************************************************
 *	@params:
 *				char* dest: destination buffer
 *				msgHeader_t header: message header holding current values
 *	@return:
 *				n/a
 *	@desc:
 *				rather than send the header struct in the message, individual members of the header are 
 *				copied in network order to the destination buffer
 ***********************************************************************************************************/
void SuncryptSocket::PackHeader(char* dest, msgHeader_t header)
{
	/* convert the header values to network order */
	uint32_t seqNum_N = htonl(header.seqNum);
	uint16_t msgSize_N = htons(header.msgSize);
	uint16_t finalBlk_N = htons(header.finalBlk);

	/* compute the offsets in the buffer to store  */
	int msgOffset = sizeof(seqNum_N);
	int finalOffset = msgOffset + sizeof(msgSize_N);

	/* copy the values into the destination buffer */
	memcpy(dest, &seqNum_N, sizeof(seqNum_N));
	memcpy(dest+msgOffset, &msgSize_N, sizeof(msgSize_N)); 
	memcpy(dest+finalOffset, &finalBlk_N, sizeof(finalBlk_N)); 
}

/************************************************************************************************************
 *	@params:
 *				char* buffer: buffer containing received message and header
 *				msgHeader_t* header: pointer to message header structure to store values
 *	@return:
 *				n/a
 *	@desc:
 *				retrieves the header information from the received message into the message header struct
 ***********************************************************************************************************/
void SuncryptSocket::GetHeader(char* buffer, msgHeader_t *header)
{
	uint32_t seqNum_N;
	uint16_t msgSize_N;
	uint16_t finalBlk_N;

	/* compute the offset of the contents of the header */ 
	int msgOffset = sizeof(seqNum_N);
	int finalOffset = msgOffset + sizeof(msgSize_N);

	/* retrieve the contents of the header from the buffer */
	memcpy(&seqNum_N, buffer, sizeof(seqNum_N));
	memcpy(&msgSize_N, buffer+msgOffset, sizeof(msgSize_N));
	memcpy(&finalBlk_N, buffer+finalOffset, sizeof(finalBlk_N));

	/* convert the contents host order, store in the header */
	header->seqNum = ntohl(seqNum_N);
	header->msgSize = ntohs(msgSize_N);
	header->finalBlk = ntohs(finalBlk_N);
}
