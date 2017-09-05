#ifndef SUNCRYPT_H
#define SUNCRYPT_H

#include "CryptoDefs.h"
#include <gcrypt.h>
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
	ERR_FILE_EXISTS	= 4
} parseErrorTypes;	

/* Suncrypt Class */
class Suncrypt
{
public:
	Suncrypt();
	~Suncrypt(){};
     int Encrypt(int numParams, char** params);

private:
     int Parse(int numParams, char** params);
     void ParseErrorMsg(int errCode);
     void GcryptErrorMsg(string errMsg, gcry_error_t errCode);
     void GetPassword(string &password);
     gcry_error_t CreateKey(string password);
     void SetAESKey(unsigned char* key, unsigned int keyLength);
     void SetHMACKey(unsigned char* key, unsigned int keyLength);
     void PrintKey(unsigned char* key, unsigned int keyLength);
     size_t DecimalToOctal(unsigned int decimal);

     string inputFileName;
     string outputFileName;
     string type;
     string ipAddr;
     string port;
     string password;
     unsigned char pbkdf2Key[PBKDF2_KEY_SIZE];
     unsigned char aesKey[AES_KEY_SIZE];
     unsigned char hmacKey[HMAC_KEY_SIZE];
};

#endif //SUNCRYPT_H