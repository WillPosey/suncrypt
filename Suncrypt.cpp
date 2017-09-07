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
 *
 **************************************************/
int main(int argc, char** argv)
{
     Suncrypt s;
     return s.Encrypt(argc, argv);
}

/**************************************************
 *
 **************************************************/
int Suncrypt::Encrypt(int numParams, char** params)
{
     int parseResult;
     unsigned char *plainText, *cipherText;
     size_t plainTextLength, cipherTextLength;

     /* Parse input, check for correct parameters */
     parseResult = Parse(numParams, params);
     if(parseResult != 0)
     {
          ParseErrorMsg(parseResult);
          return parseResult;
     }

     sunSocket = new SuncryptSocket(port);

     /* Create and display the key */
     if(!gcrypt.CreateKey(key, SUNGCRY_KEY_SIZE))
     {
          gcrypt.PrintError();
          return -1;
     }
     gcrypt.PrintKeyHex(key);

     /* Get Size of file */
     plainTextLength = fOps.GetFileSize(inputFileName);
     cipherTextLength = plainTextLength;
     if(plainTextLength < 0)
          return -1;

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

     /* Write the file, or transmit */
     if(localMode)
     {
          if(!fOps.WriteFile(outputFileName, cipherText, cipherTextLength))
               return -1;
          printf("Successfully encrypted %s to %s (%lu bytes written).\n", inputFileName.c_str(), outputFileName.c_str(), cipherTextLength);
     }
     else 
     {
          printf("Successfully encrypted %s to %s (%lu bytes written).\n", inputFileName.c_str(), outputFileName.c_str(), cipherTextLength);
          cout << "Transmitting to " << ipAddr << ":" << port << endl;
          if(sunSocket->Send(ipAddr, (char*)cipherText, cipherTextLength) != 0)
               return -1;
          cout << "Successfully received" << endl;
     }

     delete[] plainText;
     delete[] cipherText;

     return 0;
}

/**************************************************
 *
 **************************************************/
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
          port = ipAddr_port.substr(delimeter+1, ipAddr_port.size());

          localMode = false;
     }
     else
          return ERR_OPT;

     return 0;
}

/**************************************************
 *
 **************************************************/
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