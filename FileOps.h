/************************************************************************************************************
*	Author:			William Posey
*	Course: 		University of Florida, CNT 5410
*	Semester:		Fall 2017
*	Project:		Assignment 2, Suncrypt
*	File:			FileOps.h
*	Description:	This file contains the declaration of the FileOps class, which is used to
*					implement functionality related to file I/O
************************************************************************************************************/
#ifndef FILE_OPS_H
#define FILE_OPS_H

#include <string>
using std::string;

/* SuncryptSocket class declaration */
class FileOps
{
public:
	bool ReadFile(const string fileName, unsigned char* fileContent, size_t bufferSize);
	bool WriteFile(const string fileName, unsigned char* fileContent, size_t bufferSize);
	size_t GetFileSize(const string fileName);
};

#endif //FILE_OPS_H
