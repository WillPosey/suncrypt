/************************************************************************************************************
*	Author:		William Posey
*	Course: 		University of Florida, CNT 5410
*	Semester:		Fall 2017
*	Project:		Assignment 2, Suncrypt
*	File:		Suncrypt.h
*	Description:	This file contains the declaration of the Suncrypt class, which is used to
*				implement encryption of a locally stored file and either save it locally, or transmit
*				it to a destination IP address and port
************************************************************************************************************/
#ifndef SUNCRYPT_H
#define SUNCRYPT_H

#include "SunGcrypt.h"
#include "FileOps.h"
#include "SuncryptSocket.h"
#include <string>
using std::string;

/* Input parameter definitions */
#define L_NUM_PARAMS 3
#define D_NUM_PARAMS 4
#define D_OPT "-d"
#define L_OPT "-l"

/* Error code definitions */
typedef enum
{
	ERR_NUM_PARAMS		= 1,
	ERR_OPT			= 2,
	ERR_NO_FILE		= 3,
	ERR_FILE_EXISTS	= 33
} parseErrorTypes;	

/* default port to bind the socket to */
#define SUNCRYPT_PORT "45000"

/* Suncrypt class declaration */
class Suncrypt
{
public:
     int Encrypt(int numParams, char** params);

private:
     int Parse(int numParams, char** params);
     void ParseErrorMsg(int errCode);

     /* Member Variables related to program input */
     string inputFileName;
     string outputFileName;
     string type;
     string ipAddr;
     string sendPort;
     string recvPort;
     string key;
     bool localMode;

     /* Member Variables */
     SunGcrypt gcrypt;
     SuncryptSocket* sunSocket;
     FileOps fOps;
};

#endif //SUNCRYPT_H
