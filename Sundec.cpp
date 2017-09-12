/************************************************************************************************************
*    Author:        William Posey
*    Course:        University of Florida, CNT 5410
*    Semester:      Fall 2017
*    Project:       Assignment 2, Suncrypt
*    File:          Sundec.cpp
*    Description:   This file contains the definitions for the methods of the Sundec class, which is used to
*                   implement decryption of an encrypted file either stored locally, or received over network
*                   communication
************************************************************************************************************/
#include "Sundec.h"
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
     Sundec s;
     return s.Decrypt(argc, argv);
}

/************************************************************************************************************
 *   @params:
 *			int numParams: number of input parameters, passed to Parse()
 *			char** params: array of input parameters, passed to Parse()
 *   @return:
 * 			0: success
 *			33: output file exists
 *			62: Invalid HMAC signature
 *			-1: other error
 *   @desc:
 *			parses the input parameters, then decrypts the input or transmitted file
 *			checks to make sure the output file does not exist, and that the HMAC signature is valid
 ***********************************************************************************************************/
int Sundec::Decrypt(int numParams, char** params)
{
     int parseResult;
     int numBytes;
     unsigned char *plainText, *cipherText, *signedData;
     size_t plainTextLength, cipherTextLength, signedDataLength;

     /* Parse input, check for correct parameters */
     parseResult = Parse(numParams, params);
     if(parseResult != 0)
     {
          ParseErrorMsg(parseResult);
          return parseResult;
     }

     if(localMode)
     {
          /* Create and display the key */
          if(!gcrypt.CreateKey(key, SUNGCRY_KEY_SIZE))
          {
               gcrypt.PrintError();
               return -1;
          }
          gcrypt.PrintHex("Key:", key);

          /* Get Size of file */
          signedDataLength = fOps.GetFileSize(inputFileName);
          if(signedDataLength < 0)
               return -1;
          cipherTextLength = signedDataLength - gcrypt.GetHMACLength();
          plainTextLength = gcrypt.GetDecryptedLength(cipherTextLength);

          /* Allocate memory */
          signedData = new unsigned char[signedDataLength];
          cipherText = new unsigned char[cipherTextLength];
          plainText = new unsigned char[plainTextLength];

          /* Read the file */
          if(!fOps.ReadFile(inputFileName, signedData, signedDataLength))
               return -1;
     }
     else
     {
          /* Receive the encrypted file */
          cout << "Waiting for connections..." << endl;
          sunSocket = new SuncryptSocket(port);
          numBytes = sunSocket->Receive();
          if(numBytes < 0)
               return -1;
          cout << "Recevied encrypted file" << endl;

          /* Create and display the key */
          if(!gcrypt.CreateKey(key, SUNGCRY_KEY_SIZE))
          {
               gcrypt.PrintError();
               return -1;
          }
          gcrypt.PrintHex("Key:", key);

          /* allocate memory to hold the signed data, encrypted data, and decrypted data */
          signedDataLength = numBytes;
          cipherTextLength = signedDataLength - gcrypt.GetHMACLength();
          plainTextLength = gcrypt.GetDecryptedLength(cipherTextLength);
          signedData = new unsigned char[signedDataLength];
          cipherText = new unsigned char[cipherTextLength];
          plainText = new unsigned char[plainTextLength];
          sunSocket->GetRecvMsg((char*)signedData, signedDataLength);
     }

     /* Check the HMAC signature */
     if(!gcrypt.CheckHMAC(key, signedData, signedDataLength, cipherText, cipherTextLength))
     {
          gcrypt.PrintError();
          return ERR_INVAL_HMAC;
     }

     /* Decrypt the file */
     if(!gcrypt.Decrypt(key, cipherText, cipherTextLength, plainText, plainTextLength))
     {
          gcrypt.PrintError();
          return -1;
     }

     /* Write the decrypted file */
     if(!fOps.WriteFile(outputFileName, plainText, plainTextLength))
     {
          cout << "Error writing decrypted file" << endl;
          return -1;
     }

     printf("Successfully received and decrypted %s (%lu bytes written).\n", outputFileName.c_str(), plainTextLength);

     delete[] plainText;
     delete[] cipherText;
     delete[] signedData;
     return 0;
}

/************************************************************************************************************
 *   @params:
 *			int numParams: number of input parameters
 *			char** params: array of input parameters    
 *   @return:
 *			0: success
 *			33: output file exists
 *			-1: other error
 *   @desc:
 *			parses the input from the command line, and stores values to proper member variables
 *			if error occurs, an error code > 0 is returned to indicate the type of error, displayed by
 *			PrintError()
 ***********************************************************************************************************/
int Sundec::Parse(int numParams, char** params)
{
     struct stat buffer;
     int delimeter, length;
     size_t index;

     /* check number of parameters */
     if( (numParams != L_NUM_PARAMS) && (numParams != D_NUM_PARAMS) )
          return ERR_NUM_PARAMS;

     /* save input file name */
     inputFileName.assign(params[1]);

     /* save the option type */
     type.assign(params[2]);

     /* -l option */
     if( (type.compare(L_OPT) == 0) && (numParams == L_NUM_PARAMS) )
     { 
          /* make sure the input file exists */
          if( stat(inputFileName.c_str(), &buffer) != 0 )
               return ERR_NO_FILE;

          /* find index of extension */
          index = inputFileName.find_last_of(SUNGCRY_FILE_EXT);
          if(index==string::npos)
               return ERR_EXT;

          /* output file is input file with extension removed */
          outputFileName = inputFileName.substr(0, index-2);

          /* make sure output file doesn't exist */
          if( stat(outputFileName.c_str(), &buffer) == 0)
               return ERR_FILE_EXISTS;

          localMode = true;
     }
     /* -d option */
     else if( (type.compare(D_OPT) == 0) && (numParams == D_NUM_PARAMS) )
     {
          /* store port */
          port.assign(params[3]);

          outputFileName = inputFileName;

          /* make sure output file doesn't exist */
          if( stat(outputFileName.c_str(), &buffer) == 0)
               return ERR_FILE_EXISTS;

          localMode = false;
     }
     else
          return ERR_OPT;

     return 0;
}

/************************************************************************************************************
 *   @params:
 *			int errCode: error code
 *   @return:
 *			n/a 
 *   @desc:
 *			prints an error messaging corresponding to the input error code  
 ***********************************************************************************************************/
void Sundec::ParseErrorMsg(int errCode)
{
     switch(errCode)
     {
          case ERR_NUM_PARAMS:
               cout << "ERROR: Input format is <filename> [-d <port>] [-l]" << endl;
               break;
          case ERR_NO_FILE:
               cout << "ERROR: Input file does not exist" << endl;
               break;
          case ERR_FILE_EXISTS:
               cout << "ERROR: Output file exists" << endl;
               break;
          case ERR_OPT:
               cout << "ERROR: Options are [-d <port>] for network or [-l] for local" << endl;
               break;
          case ERR_EXT:
               cout << "ERROR: input file must have extension " << SUNGCRY_FILE_EXT << endl;
               break;
     }
}
