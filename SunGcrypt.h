#ifndef SUN_GCRYPT_H
#define SUN_GCRYPT_H

#include <string>
#include <gcrypt.h>

#define SUNGCRY_FILE_EXT		".uf"	/* File extension of encrypted file */
#define SUNGCRY_KEY_SIZE		16		/* Key length for used for AES128 and HMAC (in bytes) */
#define SUNGCRY_BLK_SIZE		16		/* Block size for AES128 (in bytes) */
#define SUNGCRY_SHA512_ITER		4096	/* Number of iterations to use for SHA-512 */
#define SUNGCRY_SALT			"NaCl"	/* Salt used for SHA-512 */
#define SUNGCRY_SALT_LENGTH		4		/* Length of the salt */
#define SUNGCRY_IV				5844	/* IV value to use for CBC */

using std::string;
using std::filebuf;

class SunGcrypt
{
public:
	SunGcrypt();
	bool CreateKey(string &key, size_t keyLength);
	bool Encrypt(const string key, unsigned char* plainText, size_t plainTextLength, unsigned char* cipherText, size_t cipherTextLength);
	bool Decrypt(const string key, unsigned char* cipherText, size_t cipherTextLength, unsigned char* plainText, size_t plainTextLength);
	bool AppendHMAC(const string key, unsigned char* data, unsigned int dataLength, unsigned char* signedData, unsigned int signedDataLength);
	bool CheckHMAC(const string key, unsigned char* signedData, unsigned int signedDataLength, unsigned char* cipherText, unsigned int cipherTextLength);
	unsigned int GetHMACLength();
	void PrintError();
	void PrintKeyHex(const string key);

private:
	bool OpenAESHandle();
	void CloseAESHandle();
	bool SetAESKey(const string key);
	bool SetAESIV();

	bool OpenHMACHandle();
	bool SetHMACKey(const string key);
	bool WriteHMAC(const unsigned char* dataBuffer, size_t bufferLength);
	bool ReadHMAC(unsigned char* hmacBuffer, size_t* bufferLength);
	bool VerifyHMAC(const unsigned char* hmac, size_t hmacLength);
	void CloseHMACHandle();

	size_t DecimalToOctal(unsigned int decimal);

	bool aesHandleOpen;
	gcry_cipher_hd_t aesHandle;
	gcry_mac_hd_t hmacHandle;
	gcry_error_t errCode;
	string errMsg;
};

#endif //SUN_GCRYPT_H