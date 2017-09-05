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
Suncrypt::Suncrypt()
{
      gcry_check_version(NULL);
}

/**************************************************
 *
 **************************************************/
int Suncrypt::Encrypt(int numParams, char** params)
{
     int parseResult;
     gcry_error_t error;

     /* Parse input, check for correct parameters */
     parseResult = Parse(numParams, params);
     if(parseResult != 0)
     {
          ParseErrorMsg(parseResult);
          return parseResult;
     }

     GetPassword(password);
     if(CreateKey(password) != 0)
     {
          GcryptErrorMsg("CreateKey",error);
          return -1;
     }
     PrintKey(pbkdf2Key, PBKDF2_KEY_SIZE);
     SetAESKey(pbkdf2Key, PBKDF2_KEY_SIZE);
     SetHMACKey(pbkdf2Key, PBKDF2_KEY_SIZE);

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
     outputFileName.append(FILE_EXT);
 
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

/**************************************************
 *
 **************************************************/
void Suncrypt::GcryptErrorMsg(string errMsg, gcry_error_t errCode)
{
     cout << errMsg << ": [src] " << gcry_strsource(errCode) << " [err] " << gcry_strerror(errCode) << endl;
}

/**************************************************
 *
 **************************************************/
void Suncrypt::PrintKey(unsigned char* key, unsigned int keyLength)
{
     cout << "Key: ";
     for(int i=0; i<keyLength; i++)
          printf(" %02X ", key[i]);
     cout << endl;
}

/**************************************************
 *
 **************************************************/
 void Suncrypt::GetPassword(string &password)
{
     cout << "Password: ";
     cin >> password;    
}

/**************************************************
 *
 **************************************************/
size_t Suncrypt::DecimalToOctal(unsigned int decimal)
{
     size_t octal = 0;
     unsigned int i = 1;

     while (decimal != 0)
     {
          octal += (decimal % 8) * i;
          decimal /= 8;
          i *= 10;
     }

     return octal;
}

/**************************************************
 *
 **************************************************/
gcry_error_t Suncrypt::CreateKey(string password)
{

     return gcry_kdf_derive(  password.c_str(),   // password
                              DecimalToOctal(password.size()),    // password length, octal
                              GCRY_KDF_PBKDF2,    // key derivation function
                              GCRY_MD_SHA512,     // hash algorithm used by key derivation function
                              SALT,               // salt
                              DecimalToOctal(SALT_LENGTH),        // salt length
                              SHA512_ITER,        // # iterations
                              DecimalToOctal(PBKDF2_KEY_SIZE),    // key size, octal
                              pbkdf2Key           // key buffer
                              );
}

/**************************************************
 *
 **************************************************/
void Suncrypt::SetAESKey(unsigned char* key, unsigned int keyLength)
{
     memset(aesKey, 0, AES_KEY_SIZE);
     if(keyLength <= AES_KEY_SIZE)
          memcpy(aesKey, key, keyLength);
     else
          memcpy(aesKey, key, AES_KEY_SIZE);
}

/**************************************************
 *
 **************************************************/
void Suncrypt::SetHMACKey(unsigned char* key, unsigned int keyLength)
{
     memset(hmacKey, 0, HMAC_KEY_SIZE);
     if(keyLength <= HMAC_KEY_SIZE)
          memcpy(hmacKey, key, keyLength);
     else
          memcpy(hmacKey, key, HMAC_KEY_SIZE);
}