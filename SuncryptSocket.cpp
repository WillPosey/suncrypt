#include "SuncryptSocket.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <iostream>
#include <cstring>

using std::string;
using std::cout;
using std::endl;

/***********************************************************************************
 *
 **********************************************************************************/
SuncryptSocket::SuncryptSocket(unsigned int recvPort)
{
	recvBufferGood = false;
	socketGood = false;
	recvBufferLength = 0;

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));

	addr.sin_family = AF_INET;
	addr.sin_port = recvPort;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	sockFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sockFd == -1)
		cout << "Error in SuncryptSocket Constructor: socket()" << endl;
	else if(bind(sockFd, (struct sockaddr*)&addr, sizeof(addr)) == -1)
			cout << "Error in SuncryptSocket Constructor: bind()" << endl;
	else
		socketGood = true;
}

/***********************************************************************************
 *
 **********************************************************************************/
~SuncryptSocket::SuncryptSocket()
{
	close(sockFd);
}

/***********************************************************************************
 *
 **********************************************************************************/
int SuncryptSocket::Send(const string destIP, unsigned int destPort, const char* msg, size_t msgLength)
{
	int numBlks;
	msgHeader_t msgHeader;
	char blk[BLK_SIZE];

	numBlks = msgLength / MAX_MSG_SIZE;
	if(numBlks%MAX_MSG_SIZE)
		numBlks++;

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

		//sendto

		//while(!receivedCorrectSeq)
		//	recvfrom

		msgHeader.seqNum++;
	}
}

/***********************************************************************************
 *
 **********************************************************************************/
int SuncryptSocket::Receive()
{
	delete[] recvBuffer;
	recvBufferGood = false;

	recvBufferGood = true;
}

/***********************************************************************************
 *
 **********************************************************************************/
void SuncryptSocket::GetRecvMsg(char* buffer, size_t bufferLength)
{
	int length = (recvBufferLength > bufferLength) ? bufferLength : recvBufferLength;
	if(recvBufferGood)
		memcpy(buffer, recvBuffer, length);
}