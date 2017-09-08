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
 *
 **************************************************/
int main(int argc, char** argv)
{
     Sundec s;
     return s.Decrypt(argc, argv);
}

/**************************************************
 *
 **************************************************/
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
          gcrypt.PrintKeyHex(key);

          /* Get Size of file */
          signedDataLength = fOps.GetFileSize(inputFileName);
          plainTextLength = cipherTextLength = signedDataLength - gcrypt.GetHMACLength();
          if(cipherTextLength < 0)
               return -1;

          /* Allocate memory */
          plainText = new unsigned char[plainTextLength];
          cipherText = new unsigned char[cipherTextLength];
          signedData = new unsigned char[signedDataLength];

          /* Read the file */
          if(!fOps.ReadFile(inputFileName, signedData, signedDataLength))
               return -1;
     }
     else
     {
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
          gcrypt.PrintKeyHex(key);

          signedDataLength = numBytes;
          plainTextLength = cipherTextLength = signedDataLength - gcrypt.GetHMACLength();
          plainText = new unsigned char[plainTextLength];
          cipherText = new unsigned char[cipherTextLength];
          signedData = new unsigned char[signedDataLength];
          sunSocket->GetRecvMsg((char*)signedData, signedDataLength);
     }

     /* Check the HMAC signature */
     if(!gcrypt.CheckHMAC(key, signedData, signedDataLength, cipherText, cipherTextLength))
     {
          gcrypt.PrintError();
          return 62;
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

/**************************************************
 *
 **************************************************/
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

/**************************************************
 *
 **************************************************/
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