#include "FileOps.h"
#include <iostream>
#include <fstream>

using std::ifstream;
using std::ofstream;
using std::cout;
using std::endl;
using std::filebuf;

/****************************************************************************
 *
 ***************************************************************************/
bool FileOps::ReadFile(const string fileName, unsigned char* fileContent, size_t bufferSize)
{
	ifstream ifStr;	
	filebuf* ifPtr;

	ifStr.open(fileName.c_str(), ifstream::in);
	if(!ifStr.is_open())
	{
		cout << "Error opening " << fileName << endl;
		return false;
	}

	ifPtr = ifStr.rdbuf();
	ifPtr->sgetn ((char*)fileContent,bufferSize);

	ifStr.close();
	return true;
}

/****************************************************************************
 *
 ***************************************************************************/
bool FileOps::WriteFile(const string fileName, unsigned char* fileContent, size_t bufferSize)
{
	ofstream ofStr;	

	ofStr.open(fileName.c_str(), ofstream::out);
	if(!ofStr.is_open())
	{
		cout << "Error opening " << fileName << endl;
		return false;
	}

	ofStr.write((char*)fileContent, bufferSize);
	ofStr.close();
	return true;
}

/****************************************************************************
 *
 ***************************************************************************/
size_t FileOps::GetFileSize(const string fileName)
{
	ifstream ifStr;	
	filebuf* ifPtr;
	size_t ifSize;

	ifStr.open(fileName.c_str(), ifstream::in);
	if(!ifStr.is_open())
	{
		cout << "Error getting size of " << fileName << endl;
		return -1;
	}

	ifPtr = ifStr.rdbuf();
	ifSize = ifPtr->pubseekoff (0,ifStr.end,ifStr.in);
	ifPtr->pubseekpos (0,ifStr.in);

	ifStr.close();
	return ifSize;
}