/************************************************************************************************************
*	Author:			William Posey
*	Course: 		University of Florida, CNT 5410
*	Semester:		Fall 2017
*	Project:		Assignment 2, Suncrypt
*	File:			FileOps.cpp
*	Description:	This file contains definitions for methods of the FileOps class, which is used to
*					implement functionality related to file I/O
************************************************************************************************************/
#include "FileOps.h"
#include <iostream>
#include <fstream>

using std::ifstream;
using std::ofstream;
using std::cout;
using std::endl;
using std::filebuf;

/************************************************************************************************************
 *	@params:
 *				const string filename:	name of file to read
 *				unsigned char* fileContent: buffer to store file content
 *				size_t bufferSize: size of the fileContent buffer
 *	@return:
 *				true: success
 *				false: error
 *	@desc:
 *				reads in file content to the fileContent buffer, up to the maximum buffer capacity
 ***********************************************************************************************************/
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

/************************************************************************************************************
 *	@params:
 *				const string fileName: name of the file to write to
 *				unsigned char* fileContent: buffer holding data to write to file
 *				size_t bufferSize: size of the fileContent buffer
 *	@return:
 *				true: success
 *				false: error
 *	@desc:
 *				writes the data held in fileContent buffer to the output file
 ***********************************************************************************************************/
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

/************************************************************************************************************
 *	@params:
 *				const string fileName: file name to get size of
 *	@return:
 *				-1: error occured
 *				otherwise: size of the file
 *	@desc:
 *				opens the file, reads the file size, closes the file, returns the file size
 *				this can be used to allocate storage in a buffer to read the file into
 ***********************************************************************************************************/
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
