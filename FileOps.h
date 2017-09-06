#ifndef FILE_OPS_H
#define FILE_OPS_H

#include <string>

using std::string;

class FileOps
{
public:
	bool ReadFile(const string fileName, unsigned char* fileContent, size_t bufferSize);
	bool WriteFile(const string fileName, unsigned char* fileContent, size_t bufferSize);
	size_t GetFileSize(const string fileName);
};

#endif //FILE_OPS_H