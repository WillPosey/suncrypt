/************************************************************************************************************
*	Author:			William Posey
*	Course: 		University of Florida, CNT 5410
*	Semester:		Fall 2017
*	Project:		Assignment 2, Suncrypt
*	File:			SuncryptSocket.h
*	Description:	This file contains the declaration of the SuncryptSocket class, which is used to
*					implement C UDP socket functionality, as well as related data types
************************************************************************************************************/
#ifndef SUNCRYPT_SOCKET_H
#define SUNCRYPT_SOCKET_H

#include <cstdint>
#include <vector>
#include <string>

using std::string;
using std::vector;

/* max message size that can be sent in one block */
#define MAX_MSG_SIZE 4096

/* size of the message header, equal to the indivudal sizes of the members of the msgHeader_t struct */
#define HEADER_SIZE (sizeof(uint32_t)+sizeof(uint16_t)+sizeof(uint16_t))

/* size of the block used in send and receive operations */
#define BLK_SIZE MAX_MSG_SIZE+HEADER_SIZE 

/* used to hold information about communication between sender and receiver */
typedef struct 
{
	uint32_t seqNum;
	uint16_t msgSize;
	uint16_t finalBlk;
} msgHeader_t;

/* SuncryptSocket class declaration */
class SuncryptSocket
{
public:
	SuncryptSocket(const string recvPortNum, const string sendPortNum = "");
	~SuncryptSocket();
	int Send(const string destIP, const char* msg, size_t msgLength);
	int Receive();
	void GetRecvMsg(char* buffer, size_t bufferLength);
	
private:
	void PackHeader(char* dest, msgHeader_t header);
	void GetHeader(char* buffer, msgHeader_t* header);

	/* Member Variables */
	int sockFd;
	bool socketGood;
	string sendPort;
	string recvPort;
	vector<char> recvBuffer;
	unsigned int recvBufferLength;
	bool recvBufferGood;
};

#endif //SUNCRYPT_SOCKET_H