#include "Suncrypt.h"
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <string.h>
#include <gcrypt.h>

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
     /* Parse input, check for correct parameters */
     int parseResult = Parse(numParams, params);
     if(parseResult != 0)
     {
          PrintErrorMsg(parseResult);
          return parseResult;
     }

     GetPassword(password);
     CreateKey(password);

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
void Suncrypt::PrintErrorMsg(int errCode)
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
 void Suncrypt::GetPassword(string &password)
 {
     cout << "Password: ";
     cin >> password;
 }

/**************************************************
 *
 **************************************************/
 void Suncrypt::CreateKey(string password)
 {

     gcry_kdf_derive(    password.c_str(),   // password
                         password.size(),    // password length, octal
                         GCRY_KDF_PBKDF2,    // key derivation function
                         //sub               // hash algorithm used by key derivation function
                         "NaCl",             // salt
                         4,                  // salt length
                         4096,               // # iterations
                         16,                // key size, octal
                         key                 // key buffer
                         );
 }