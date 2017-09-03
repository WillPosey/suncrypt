#ifndef SUNCRYPT_H
#define SUNCRYPT_H

#include <string>

using std::string;

/* Input parameter definitions */
#define L_NUM_PARAMS 3
#define D_NUM_PARAMS 4
#define D_OPT "-d"
#define L_OPT "-l"

/* Error code definitions */
#define ERR_NUM_PARAMS	1
#define ERR_OPT		2
#define ERR_NO_FILE		3
#define ERR_FILE_EXISTS	4		

/* File extension of encrypted file */
#define FILE_EXT	".uf"

/* Key size is 128 bits for AES-128, or 16 bytes */
#define KEY_SIZE 16

/* salt used for PBKDF2, SHA-512 */
#define SALT "NaCl"
#define SALT_LEN 4
#define ITER 4096

/* Suncrypt Class */
class Suncrypt
{
public:
	Suncrypt();
	~Suncrypt(){};
     int Encrypt(int numParams, char** params);

private:
     int Parse(int numParams, char** params);
     void PrintErrorMsg(int errCode);
     void GetPassword(string &password);
     void CreateKey(string password);

     string inputFileName;
     string outputFileName;
     string type;
     string ipAddr;
     string port;
     string password;
     char key[KEY_SIZE];
};

#endif //SUNCRYPT_H