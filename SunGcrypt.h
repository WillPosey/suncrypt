/************************************************************************************************************
*	Author:			William Posey
*	Course: 		University of Florida, CNT 5410
*	Semester:		Fall 2017
*	Project:		Assignment 2, Suncrypt
*	File:			SunGcrypt.h
*	Description:	This file contains the declaration of the SunGcrypt class, which is used to
*					implement functionality from the libgcrypt library
************************************************************************************************************/
#ifndef SUN_GCRYPT_H
#define SUN_GCRYPT_H

#include <string>
#include <gcrypt.h>

using std::string;
using std::filebuf;

#define SUNGCRY_FILE_EXT		".uf"	/* File extension of encrypted file */
#define SUNGCRY_KEY_SIZE		16		/* Key length for used for AES128 and HMAC (in bytes) */
#define SUNGCRY_BLK_SIZE		16		/* Block size for AES128 (in bytes) */
#define SUNGCRY_SHA512_ITER		4096	/* Number of iterations to use for SHA-512 */
#define SUNGCRY_SALT			"NaCl"	/* Salt used for SHA-512 */
#define SUNGCRY_SALT_LENGTH		4		/* Length of the salt */
#define SUNGCRY_IV				5844	/* IV value to use for CBC */

/* SunGcrypt Class Declaration */
class SunGcrypt
{
public:
	SunGcrypt();
	void PrintError();

	/* Public methods related to key derivation */
	bool CreateKey(string &key, size_t keyLength);
	void PrintHex(const string msg, const string data, unsigned int numCols=0);

	/* Public methods related to AES */
	bool Encrypt(const string key, unsigned char* plainText, size_t plainTextLength, unsigned char* cipherText, unsigned int cipherTextLength);
	bool Decrypt(const string key, unsigned char* cipherText, unsigned int cipherTextLength, unsigned char* plainText, unsigned int plainTextLength);
	unsigned int GetEncryptedLength(unsigned int plainTextLength);
	unsigned int GetDecryptedLength(unsigned int cipherTextLength);

	/* Public methods related to HMAC */
	bool AppendHMAC(const string key, unsigned char* data, unsigned int dataLength, unsigned char* signedData, unsigned int signedDataLength);
	bool CheckHMAC(const string key, unsigned char* signedData, unsigned int signedDataLength, unsigned char* cipherText, unsigned int cipherTextLength);
	unsigned int GetHMACLength();
	void PrintHash(const string msg, const unsigned char* buffer, unsigned int bufferLength);

private:
	/* Private Methods related to AES */
	bool OpenAESHandle();
	void CloseAESHandle();
	bool SetAESKey(const string key);
	bool SetAESIV();
	void GetIV(unsigned char* ivBuffer, unsigned int ivBufferLength);
	void GetNonce(unsigned char* nonceBuffer, unsigned int nonceBufferLength);

	size_t DecimalToOctal(unsigned int decimal);

	/* Member Variables */
	bool aesHandleOpen;
	gcry_cipher_hd_t aesHandle;
	gcry_error_t errCode;
	string errMsg;
};

#endif //SUN_GCRYPT_H
