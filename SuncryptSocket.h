#ifndef SUNCRYPT_SOCKET_H
#define SUNCRYPT_SOCKET_H

#include <cstdint>
#include <vector>

#define MAX_MSG_SIZE 4096
#define HEADER_SIZE sizeof(msgHeader_t)
#define BLK_SIZE MAX_MSG_SIZE+HEADER_SIZE 

using std::string;
using std::vector;

typedef struct 
{
	uint64_t seqNum;
	uint16_t msgSize;
	uint8_t finalBlk;
} msgHeader_t;

class SuncryptSocket
{
public:
	SuncryptSocket(unsigned int recvPort);
	~SuncryptSocket();
	int Send(const string destIP, unsigned int destPort, const char* msg, size_t msgLength);
	int Receive();
	void GetRecvMsg(char* buffer, size_t bufferLength);
private:
	int sockFd;
	bool socketGood;
	vector<char> recvBuffer;
	unsigned int recvBufferLength;
	bool recvBufferGood;
};

#endif //SUNCRYPT_SOCKET_H