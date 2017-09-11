/************************************************************************************************************
*    Author:        William Posey
*    Course:        University of Florida, CNT 5410
*    Semester:      Fall 2017
*    Project:       Assignment 2, Suncrypt
*    File:          Suncrypt.cpp
*    Description:   This file contains the definitions for the methods of the Suncrypt class, which is used
*                   to implement encryption of a locally stored file and either save it locally, or transmit
*                   it to a destination IP address and port
************************************************************************************************************/
#include "Suncrypt.h"
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <cstring>
#include <cstdio>

using std::cout;
using std::cin;
using std::endl;
using std::string;

/**************************************************
 *                  Main Method
 **************************************************/
int main(int argc, char** argv)
{
     Suncrypt s;
     return s.Encrypt(argc, argv);
}

/************************************************************************************************************
 *   @params:
 *             int numParams: number of input parameters, passed to Parse()
 *             char** params: array of input parameters, passed to Parse()
 *   @return:
 *             0: success
 *             33: output file exists
 *             -1: other error
 *   @desc:
 *             parses the input parameters, then encrypts the input file
 *             the encrypted input file is signed with an HMAC and appends the HMAC to the encrypted file
 *             either saves the encrypted file locally, or transmits it to a receiver over the network
 ***********************************************************************************************************/
int Suncrypt::Encrypt(int numParams, char** params)
{
     int parseResult;
     unsigned char *plainText, *cipherText, *signedData;
     size_t plainTextLength, cipherTextLength, signedDataLength;

     /* Parse input, check for correct parameters */
     parseResult = Parse(numParams, params);
     if(parseResult != 0)
     {
          ParseErrorMsg(parseResult);
          return parseResult;
     }

     /* make sure sendPort and recvPort are different, in the case suncrypt, sundec are on the same machine */
     recvPort = (sendPort.compare(SUNCRYPT_PORT)==0) ? std::to_string(atoi(SUNCRYPT_PORT)+1) : SUNCRYPT_PORT;
     sunSocket = new SuncryptSocket(recvPort, sendPort);

     /* Create and display the key */
     if(!gcrypt.CreateKey(key, SUNGCRY_KEY_SIZE))
     {
          gcrypt.PrintError();
          return -1;
     }
     gcrypt.PrintKeyHex(key);

     /* Get Size of file */
     plainTextLength = fOps.GetFileSize(inputFileName);
     if(plainTextLength < 0)
          return -1;
     cipherTextLength = gcrypt.GetEncryptedLength(plainTextLength);

     /* Allocate memory */
     plainText = new unsigned char[plainTextLength];
     cipherText = new unsigned char[cipherTextLength];

     /* Read the input file */
     if(!fOps.ReadFile(inputFileName, plainText, plainTextLength))
          return -1;

     /* Encrypt the file */
     if(!gcrypt.Encrypt(key, plainText, plainTextLength, cipherText, cipherTextLength))
     {
          gcrypt.PrintError();
          return -1;
     }

     /* Sign the data */
     signedDataLength = cipherTextLength + gcrypt.GetHMACLength();
     signedData = new unsigned char[signedDataLength];
     if(!gcrypt.AppendHMAC(key, cipherText, cipherTextLength, signedData, signedDataLength))
     {
          gcrypt.PrintError();
          return -1;
     }

     /* Write the file, or transmit */
     if(localMode)
     {
          if(!fOps.WriteFile(outputFileName, signedData, signedDataLength))
               return -1;
          printf("Successfully encrypted %s to %s (%lu bytes written).\n", inputFileName.c_str(), outputFileName.c_str(), signedDataLength);
     }
     else 
     {
          printf("Successfully encrypted %s to %s (%lu bytes written).\n", inputFileName.c_str(), outputFileName.c_str(), signedDataLength);
          cout << "Transmitting to " << ipAddr << ":" << sendPort << endl;
          if(sunSocket->Send(ipAddr, (char*)signedData, signedDataLength) != 0)
               return -1;
          cout << "Successfully received" << endl;
     }

     delete[] plainText;
     delete[] cipherText;
     delete[] signedData;
     return 0;
}

/************************************************************************************************************
 *   @params:
 *             int numParams: number of input parameters
 *             char** params: array of input parameters    
 *   @return:
 *             0: success
 *             33: output file exists
 *             -1: other error
 *   @desc:
 *             parses the input from the command line, and stores values to proper member variables
 *             if error occurs, an error code > 0 is returned to indicate the type of error, displayed by
 *             PrintError()
 ***********************************************************************************************************/
int Suncrypt::Parse(int numParams, char** params)
{
     struct stat buffer;
     int delimeter, length;
     string ipAddr_port;  

     /* check number of parameters */
     if( (numParams != L_NUM_PARAMS) && (numParams != D_NUM_PARAMS) )
          return ERR_NUM_PARAMS;

     /* save input file name, create output file name */
     inputFileName.assign(params[1]);
     outputFileName = inputFileName;
     outputFileName.append(SUNGCRY_FILE_EXT);
 
     /* make sure the input file exists */
     if( stat(inputFileName.c_str(), &buffer) != 0 )
          return ERR_NO_FILE;

     /* save the option type */
     type.assign(params[2]);

     /* -l option */
     if( (type.compare(L_OPT) == 0) && (numParams == L_NUM_PARAMS) )
     {
          /* make sure output file doesn't exist */
          if( stat(outputFileName.c_str(), &buffer) == 0)
               return ERR_FILE_EXISTS;

          localMode = true;
     }
     /* -d option */
     else if( (type.compare(D_OPT) == 0) && (numParams == D_NUM_PARAMS) )
     {
          /* temporarily store ipAddr:port */
          ipAddr_port.assign(params[3]);

          /* at a minimum, input should be of length 9 */
          /* ex: 1.1.1.1:1 */
          if(ipAddr_port.size() < 9)
               return ERR_OPT;

          /* find index of separator */
          delimeter = ipAddr_port.find(':');
          if(delimeter == string::npos)
               return ERR_OPT;

          /* assign IP and port */
          ipAddr = ipAddr_port.substr(0,delimeter);
          sendPort = ipAddr_port.substr(delimeter+1, ipAddr_port.size());

          localMode = false;
     }
     else
          return ERR_OPT;

     return 0;
}

/************************************************************************************************************
 *   @params:
 *             int errCode: error code
 *   @return:
 *             n/a 
 *   @desc:
 *             prints an error messaging corresponding to the input error code  
 ***********************************************************************************************************/
void Suncrypt::ParseErrorMsg(int errCode)
{
     switch(errCode)
     {
          case ERR_NUM_PARAMS:
               cout << "ERROR: Input format is <filename> [-d <IPaddr>:<port>] [-l]" << endl;
               break;
          case ERR_NO_FILE:
               cout << "ERROR: Input file does not exist" << endl;
               break;
          case ERR_FILE_EXISTS:
               cout << "ERROR: Output file exists" << endl;
               break;
          case ERR_OPT:
               cout << "ERROR: Options are [-d <IPaddr>:<port>] for network or [-l] for local" << endl;
               break;
     }
}
