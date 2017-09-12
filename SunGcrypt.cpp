/************************************************************************************************************
*	Author:			William Posey
*	Course: 		University of Florida, CNT 5410
*	Semester:		Fall 2017
*	Project:		Assignment 2, Suncrypt
*	File:			SunGcrypt.h
*	Description:	This file contains definitions for methods of the SunGcrypt class, which is used to
*					implement functionality from the libgcrypt library
************************************************************************************************************/
#include "SunGcrypt.h"
#include <iostream>
#include <fstream>
#include <cstdio>

using std::cout;
using std::cin;
using std::endl;
using std::ifstream;
using std::ofstream;
using std::filebuf;

/************************************************************************************************************
 *	@params:
 *				n/a
 *	@return:
 *				n/a
 *	@desc:
 *				initializes the libgcrypt library, sets flag to indicate aes handle not open
 ***********************************************************************************************************/
SunGcrypt::SunGcrypt()
{
	gcry_check_version(NULL);
	aesHandleOpen = false;
}

/************************************************************************************************************
 *	@params:
 *				string &key: string to store the created key in
 *				size_t keyLength: length of the desired key
 *	@return:
 *				true: success
 *				false: error
 *	@desc:
 *				wraps the gcry_kdf_derive function, utilizes PBKDF2 with SHA-512
 ***********************************************************************************************************/
bool SunGcrypt::CreateKey(string &key, size_t keyLength)
{
	string password;
	char keyBuffer[keyLength];

	cout << "Password: ";
    cin >> password;

    /* key derivation: PBKDF2 using SHA512 with 4 byte salt over 4096 iterartions into 128 bit key */
    errCode = gcry_kdf_derive(	password.c_str(),   				// password
								DecimalToOctal(password.size()),    // password length, octal
								GCRY_KDF_PBKDF2,    				// key derivation function
								GCRY_MD_SHA512,     				// hash algorithm used by key derivation function
								SUNGCRY_SALT,               		// salt
								DecimalToOctal(SUNGCRY_SALT_LENGTH),// salt length
								SUNGCRY_SHA512_ITER,        		// # iterations
								DecimalToOctal(keyLength),			// key size, octal
								keyBuffer);           				// key buffer
    if(errCode)
    {
    	errMsg = "SunGcrypt::CreateKey()";
    	return false;
    }

    key = string(keyBuffer,keyLength);
    return true;
}

/************************************************************************************************************
 *	@params:
 *				unsigned int plainTextLength: length of plain text
 *	@return:
 *				length of the corresponding cipher text length
 *	@desc:
 *				returns the length of the encrypted message for the given plain text length (accounts for
 *				handling of message sizes less than a block being appended by a block)
 ***********************************************************************************************************/
unsigned int SunGcrypt::GetEncryptedLength(unsigned int plainTextLength)
{
	return plainTextLength + SUNGCRY_BLK_SIZE;
}

/************************************************************************************************************
 *	@params:
 *				unsigned int cipherTextLength: length of cipher text
 *	@return:
 *				length of the corresponding plain text length
 *	@desc:
 *				returns the length of the decrypted message for the given cipher text length (accounts for
 *				handling of message sizes less than a block being appended by a block)
 ***********************************************************************************************************/
unsigned int SunGcrypt::GetDecryptedLength(unsigned int cipherTextLength)
{
	return cipherTextLength - SUNGCRY_BLK_SIZE;
}

/************************************************************************************************************
 *	@params:
 *				const string key: string containing the AES key to encrypt with
 *				unsigned char* plainText: buffer holding the data to encrypt
 *				size_t plainTextLength: length of the plainText buffer
 *				unsigned char* cipherText: buffer to hold the resulting encrypted data
 *				unsigned int cipherTextLength: length of the cipherText buffer
 *	@return:
 *				true: success
 *				false: error
 *	@desc:
 *				wraps the gcry_cipher_encrypt function
 *				first opens a handle for AES-128 with CBC and CTS, then sets the key and IV
 *				ensures that the plain text provided is at least greater than 1 block in length by appending
 *				the IV to the plaintext
 *				after encrypting the appended plain text, the encrypted result is copied into the cipherText
 *				buffer
 *				the 
 ***********************************************************************************************************/
bool SunGcrypt::Encrypt(const string key, unsigned char* plainText, size_t plainTextLength, unsigned char* cipherText, unsigned int cipherTextLength)
{
	/* ensure the cipherText buffer has enough space to store the encrypted data */
	unsigned int bufferLength = GetEncryptedLength(plainTextLength);
	if(cipherTextLength < bufferLength)
	{
		errMsg = "";
		cout << "SunGcrypt::Encrypt() cipher text buffer too small" << endl;
		return false;
	}

	/* Initialize the aesHandle */
	if(!OpenAESHandle())
		return false;

	/* set the key for the aesHandle */
	if(!SetAESKey(key))
	{
		CloseAESHandle();
		return false;
	}

	/* set the IV value for the aesHandle */
	if(!SetAESIV())
	{
		CloseAESHandle();
		return false;
	}

	/* create a buffer to store the plain text appened by a single block containing a nonce, in order */
	/* to ensure the plain text is at least greater than 1 block in length, for CTS */
	char buffer[bufferLength];
	memcpy(buffer, plainText, plainTextLength);
	unsigned char nonce[SUNGCRY_BLK_SIZE];
	GetNonce(nonce, SUNGCRY_BLK_SIZE);
	memcpy(buffer+plainTextLength, nonce, SUNGCRY_BLK_SIZE);

	/* encrypt the buffer, in place */
	errCode = gcry_cipher_encrypt(aesHandle, buffer, bufferLength, NULL, 0);
	if(errCode)
	{
		errMsg = "SunGcrypt::Encrypt()";
		CloseAESHandle();
		return false;
	}

	/* store back the result */
	memcpy(cipherText, buffer, bufferLength);
	CloseAESHandle();
	return true;
}

/************************************************************************************************************
 *	@params:
 *				const string key: string containing the AES key to decrypt with
 *				unsigned char* cipherText: buffer containing the encrypted data
 *				unsigned int cipherTextLength: length of the cipherText buffer
 *				unsigned char* plainText: buffer to store the plain text after decryption is complete
 *				size_t plainTextLength: length of the plainText buffer
 *	@return:
 *				true: success
 *				false: error
 *	@desc:
 *				wraps the gcry_cipher_decrypt function
 *				first opens a handle for AES-128 with CBC and CTS, then sets the key and IV
 *				the encrypted cipher text was appended by a block containing a nonce value, so after 
 * 				decryption this block is removed, and then the result is copied into the plainText buffer
 ***********************************************************************************************************/
bool SunGcrypt::Decrypt(const string key, unsigned char* cipherText, unsigned int cipherTextLength, unsigned char* plainText, unsigned int plainTextLength)
{
	/* ensure the plainText buffer has enough space to store the decrypted buffer */
	unsigned int reqbufferLength = GetDecryptedLength(cipherTextLength);
	if(plainTextLength < reqbufferLength)
	{
		errMsg = "";
		cout << "SunGcrypt::Decrypt() plain text buffer is too small" << endl;
		return false;
	}

	/* Initialize the aesHandle */
	if(!OpenAESHandle())
		return false;

	/* set the key for the aesHandle */
	if(!SetAESKey(key))
	{
		CloseAESHandle();
		return false;
	}

	/* set the IV value for the aesHandle */
	if(!SetAESIV())
	{
		CloseAESHandle();
		return false;
	}

	/* copy cipherText into a buffer */
	unsigned char buffer[cipherTextLength];
	memcpy(buffer, cipherText, cipherTextLength);

	/* decrypt the buffer in place */
	errCode = gcry_cipher_decrypt(aesHandle, buffer, cipherTextLength, NULL, 0);
	if(errCode)
	{
		errMsg = "SunGcrypt::Decrypt()";
		CloseAESHandle();
		return false;
	}

	/* copy the decrypted data to plainText buffer */
	memcpy(plainText, buffer, cipherTextLength-SUNGCRY_BLK_SIZE);
	CloseAESHandle();
	return true;
}

/************************************************************************************************************
 *	@params:
 *				const string msg: string to be printed before hex values
 *				const string data: string holding data to print
 *	@return:
 *				n/a
 *	@desc:
 *				displays the hexadecimal representation of the input data
 ***********************************************************************************************************/
void SunGcrypt::PrintHex(const string msg, const string data, unsigned int numCols)
{
	cout << msg;
	for(int i=0; i<data.size(); i++)
	{
		if(numCols!=0 && (i%numCols)==0)
			printf("\n\t");
		printf(" %02X ", (unsigned char)data[i]);
	}
	cout << endl;
}

/************************************************************************************************************
 *	@params:
 *				const unsigned char* buffer: buffer holding data to print hash for
 *				unsigned int bufferLength: length of buffer
 *	@return:
 *				n/a
 *	@desc:
 *				displays the hexadecimal representation of the hash of the data in the buffer
 ***********************************************************************************************************/
void SunGcrypt::PrintHash(const string msg, const unsigned char* buffer, unsigned int bufferLength)
{
	unsigned int hashLength = GetHMACLength();
	char hash[hashLength];

	gcry_md_hash_buffer(GCRY_MD_SHA512, hash, buffer, bufferLength);

	PrintHex(msg, string((char*)buffer, bufferLength), 8);
}

/************************************************************************************************************
 *	@params:
 *				n/a
 *	@return:
 *				n/a
 *	@desc:
 *				prints the error associated with the libgcry API
 ***********************************************************************************************************/
void SunGcrypt::PrintError()
{
	if(errMsg.compare("") == 0)
		return;
	cout << errMsg << ": [source] " << gcry_strsource(errCode) << " [error] " << gcry_strerror(errCode) << endl;
}

/************************************************************************************************************
 *	@params:
 *				n/a
 *	@return:
 *				true: success
 *				false: error
 *	@desc:
 *				opens a new handle for AES128 with CBC mode, and CTS for arbitrary message size
 *				wraps the gcry_cipher_open function
 ***********************************************************************************************************/
bool SunGcrypt::OpenAESHandle()
{
	if(!aesHandleOpen)
	{
		errCode = gcry_cipher_open(&aesHandle, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);

		if(errCode)
		{
			errMsg = "SunGcrypt::OpenAESHandle()";
			return false;
		}
		return true;
	}
	return true;
}

/************************************************************************************************************
 *	@params:
 *				n/a
 *	@return:
 *				n/a
 *	@desc:
 *				closes the handle used for AES, wraps the gcry_cipher_close function
 ***********************************************************************************************************/
void SunGcrypt::CloseAESHandle()
{
	if(aesHandleOpen)
	{
		gcry_cipher_close(aesHandle);
		aesHandleOpen = false;
	}
}

/************************************************************************************************************
 *	@params:
 *				const string key: string containing the AES key
 *	@return:
 *				true: success
 *				false: error	
 *	@desc:
 *				wraps the gcry_cipher_setkey function
 ***********************************************************************************************************/
bool SunGcrypt::SetAESKey(const string key)
{
	errCode = gcry_cipher_setkey(aesHandle, key.c_str(), key.size());

	if(errCode)
    {
    	errMsg = "SunGcrypt::SetAESKey()";
    	return false;
    }

    return true;
}

/************************************************************************************************************
 *	@params:
 *				n/a
 *	@return:
 *				true: success
 *				false: error	
 *	@desc:
 *				wraps the gcry_cipher_setiv function
 ***********************************************************************************************************/
bool SunGcrypt::SetAESIV()
{
	unsigned char iv[SUNGCRY_BLK_SIZE];
	GetIV(iv , SUNGCRY_BLK_SIZE);

	errCode = gcry_cipher_setiv(aesHandle, iv, SUNGCRY_BLK_SIZE);

	if(errCode)
    {
    	errMsg = "SunGcrypt::SetAESIV()";
    	return false;
    }

	return true;
}

/************************************************************************************************************
 *	@params:
 *				unsigned char* ivBuffer: buffer to store the IV
 *				unsigned int ivBufferLength: length of the ivBuffer
 *	@return:
 *				n/a
 *	@desc:
 *				copies the IV value SUNGCRY_IV into the input ivBuffer
 ***********************************************************************************************************/
void SunGcrypt::GetIV(unsigned char* ivBuffer, unsigned int ivBufferLength)
{
	int16_t ivVal = SUNGCRY_IV;
	if(ivBuffer != NULL && ivBufferLength > sizeof(ivVal))
	{
		memset(ivBuffer, 0, ivBufferLength);
		memcpy(ivBuffer, &ivVal, sizeof(ivVal));
	}
}


/************************************************************************************************************
 *	@params:
 *				unsigned char* nonceBuffer: buffer to store the nonce value
 *				unsigned int nonceBufferLength: length of the nonceBuffer
 *	@return:
 *				n/a
 *	@desc:
 *				wraps the gcry_create_nonce function
 *				copies a nonce value into the nonceBuffer
 ***********************************************************************************************************/
void SunGcrypt::GetNonce(unsigned char* nonceBuffer, unsigned int nonceBufferLength)
{
	gcry_create_nonce(nonceBuffer, nonceBufferLength);
}

/************************************************************************************************************
 *	@params:
 *				unsigned int decimal: decimal value
 *	@return:
 *				octal representation of decimal value
 *	@desc:
 *				converts the input decimal value into octal
 ***********************************************************************************************************/
size_t SunGcrypt::DecimalToOctal(unsigned int decimal)
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

/************************************************************************************************************
 *	@params:
 *				const string key: buffer holding the HMAC key
 *				unsigned char* data: buffer holding the data to create the HMAC with and append by the HMAC
 *				unsigned int dataLength: length of the data buffer
 *				unsigned char* signedData: buffer to hold the encrypted data appended by the HMAC, on success
 *				unsigned int signedDataLength: length of the signedData buffer
 *	@return:
 *				true: success
 *				false: error	
 *	@desc:
 *				encapsulates libgcrypt HMAC wrapper methods to open a HMAC handle, set the key, write the 
 *				HMAC, and then read the HMAC value
 *				the contents of the data buffer are copied to the signedData buffer, followed by the 
 *				HMAC read
 *				the signedData buffer must have length allocated equal to the length of the data buffer 
 *				plus the length of the HMAC
 ***********************************************************************************************************/
bool SunGcrypt::AppendHMAC(const string key, unsigned char* data, unsigned int dataLength, unsigned char* signedData, unsigned int signedDataLength)
{
	/* ensure the signedData buffer has space for both the encrypted data and the HMAC signature */
	unsigned int hmacLength = GetHMACLength();
	if(signedDataLength < dataLength+hmacLength)
	{
		cout << "Error SunGcrypt::AppendHMAC() signed data buffer too small" << endl;
		return false;
	}

	unsigned char hmac[hmacLength];
	unsigned char keyBuffer[key.size()];
	memcpy(keyBuffer, key.c_str(), key.size());

	gcry_buffer_t hmacdata[2];
	memset(hmacdata, 0, 2*sizeof(gcry_buffer_t));
	hmacdata[0].data = keyBuffer;
	hmacdata[0].len = key.size();
	hmacdata[1].data = data;
	hmacdata[1].len = dataLength;

	errCode = gcry_md_hash_buffers(GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC, hmac, hmacdata, 2);
	if(errCode)
	{
		errMsg = "SunGcrypt::AppendHMAC()-->gcry_md_hash_buffers()";
		return false;
	}
	PrintHex("Appended HMAC:", string((char*)hmac, hmacLength), 8);

	memcpy(signedData, data, dataLength);
	memcpy(signedData+dataLength, hmac, hmacLength);
	return true;
}

/************************************************************************************************************
 *	@params:
 *				const string key: buffer holding the HMAC key
 *				unsigned char* signedData: buffer holding the encrypted data appended by its HMAC signature
 *				unsigned int signedDataLength: length of the signedData buffer
 *				unsigned char* cipherText: buffer to hold the encrypted data from signedData, if it's valid
 *				unsigned int cipherTextLength: length of the cipherText buffer
 *	@return:
 *				true: hmac valid
 *				false: hmac invalid
 *	@desc:
 *				encapsulates libgcrypt wrapper methods to open a HMAC handle, set the key, write the HMAC,
 *				and then verify the HMAC
 *				if the encrypted data held in the signedData buffer has a valid HMAC located at the end
 *				of the buffer, the encrypted data is copied to the cipherText buffer
 ***********************************************************************************************************/
bool SunGcrypt::CheckHMAC(const string key, unsigned char* signedData, unsigned int signedDataLength, unsigned char* cipherText, unsigned int cipherTextLength)
{
	unsigned int hmacLength = GetHMACLength();
	unsigned char hmac[hmacLength], signedHmac[hmacLength];
	unsigned char keyBuffer[key.size()];

	memcpy(keyBuffer, key.c_str(), key.size());
	memcpy(signedHmac, signedData+(signedDataLength-hmacLength), hmacLength);

	gcry_buffer_t hmacdata[2];
	memset(hmacdata, 0, 2*sizeof(gcry_buffer_t));
	hmacdata[0].data = keyBuffer;
	hmacdata[0].len = key.size();
	hmacdata[1].data = signedData;
	hmacdata[1].len = signedDataLength-hmacLength;

	errCode = gcry_md_hash_buffers(GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC, hmac, hmacdata, 2);
	if(errCode)
	{
		errMsg = "SunGcrypt::CheckHMAC()-->gcry_md_hash_buffers()";
		return false;
	}
	PrintHex("Appended HMAC:", string((char*)hmac, hmacLength), 8);
	PrintHex("Read HMAC:", string((char*)signedHmac, hmacLength), 8);

	if(strncmp((char*)hmac, (char*)signedHmac, hmacLength) != 0)
	{
		errMsg = "";
		cout << "Invalid HMAC" << endl;
		return false;
	}

	memcpy(cipherText, signedData, signedDataLength-hmacLength);
	return true;
}

/************************************************************************************************************
 *	@params:
 *				n/a
 *	@return:
 *				length of the HMAC for GCRY_MAC_HMAC_SHA512
 *	@desc:
 *				returns the length of the HMAC for GCRY_MAC_HMAC_SHA512, in order to allocate space to store
 *				the HMAC in a buffer
 ***********************************************************************************************************/
unsigned int SunGcrypt::GetHMACLength()
{
	return gcry_md_get_algo_dlen(GCRY_MD_SHA512);
}
