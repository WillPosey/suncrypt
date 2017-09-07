#ifndef SUNCRYPT_SOCKET_H
#define SUNCRYPT_SOCKET_H

#include <cstdint>
#include <vector>
#include <string>

#define MAX_MSG_SIZE 4096
#define HEADER_SIZE (sizeof(uint32_t)+sizeof(uint16_t)+sizeof(uint16_t))
#define BLK_SIZE MAX_MSG_SIZE+HEADER_SIZE 

using std::string;
using std::vector;

typedef struct 
{
	uint32_t seqNum;
	uint16_t msgSize;
	uint16_t finalBlk;
} msgHeader_t;

class SuncryptSocket
{
public:
	SuncryptSocket(const string portNum);
	~SuncryptSocket();
	int Send(const string destIP, const char* msg, size_t msgLength);
	int Receive();
	void GetRecvMsg(char* buffer, size_t bufferLength);
private:
	void PackHeader(char* dest, msgHeader_t header);
	void GetHeader(char* buffer, msgHeader_t* header);

	int sockFd;
	bool socketGood;
	string port;
	vector<char> recvBuffer;
	unsigned int recvBufferLength;
	bool recvBufferGood;
};

#endif //SUNCRYPT_SOCKET_H