/************************************************************************************************************
*	Author:		William Posey
*	Course:		University of Florida, CNT 5410
*	Semester:		Fall 2017
*	Project:		Assignment 2, Suncrypt
*	File:		Sundec.h
*	Description:   This file contains the declaration of the Sundec class, which is used to implement
*				decryption of an encrypted file either stored locally, or received over network
*				communication
************************************************************************************************************/
#ifndef SUNDEC_H
#define SUNDEC_H

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
     ERR_EXT             = 4,
     ERR_FILE_EXISTS     = 33,
     ERR_INVAL_HMAC      = 62,
} parseErrorTypes;	

/* Sundec class declaration */
class Sundec
{
public:
     int Decrypt(int numParams, char** params);

private:
     int Parse(int numParams, char** params);
     void ParseErrorMsg(int errCode);

     /* Member Variables related to program input */
     string inputFileName;
     string outputFileName;
     string type;
     string port;
     string key;
     bool localMode;

     /* Member Variables */
     SunGcrypt gcrypt;
     SuncryptSocket* sunSocket;
     FileOps fOps;
};

#endif //SUNDEC_H