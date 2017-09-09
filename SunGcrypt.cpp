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
 *				
 ***********************************************************************************************************/
bool SunGcrypt::CreateKey(string &key, size_t keyLength)
{
	string password;
	char keyBuffer[keyLength];

	cout << "Password: ";
    cin >> password;

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
 *				const string key:
 *				unsigned char* plainText:
 *				size_t plainTextLength:
 *				unsigned char* cipherText:
 *				unsigned int cipherTextLength:
 *	@return:
 *				true: success
 *				false: error
 *	@desc:
 *				
 ***********************************************************************************************************/
bool SunGcrypt::Encrypt(const string key, unsigned char* plainText, size_t plainTextLength, unsigned char* cipherText, unsigned int cipherTextLength)
{
	unsigned int bufferLength = GetEncryptedLength(plainTextLength);
	if(cipherTextLength < bufferLength)
	{
		errMsg = "";
		cout << "SunGcrypt::Encrypt() cipher text buffer too small" << endl;
		return false;
	}

	if(!OpenAESHandle())
		return false;

	if(!SetAESKey(key))
		return false;

	if(!SetAESIV())
		return false;

	char buffer[bufferLength];
	memcpy(buffer, plainText, plainTextLength);
	unsigned char iv[SUNGCRY_BLK_SIZE];
	GetIV(iv , SUNGCRY_BLK_SIZE);
	memcpy(buffer+plainTextLength, iv, SUNGCRY_BLK_SIZE);

	errCode = gcry_cipher_encrypt(aesHandle, buffer, bufferLength, NULL, 0);
	if(errCode)
	{
		errMsg = "SunGcrypt::Encrypt()";
		return false;
	}

	memcpy(cipherText, buffer, bufferLength);
	CloseAESHandle();
	return true;
}

/************************************************************************************************************
 *	@params:
 *				const string key:
 *				unsigned char* cipherText:
 *				unsigned int cipherTextLength:
 *				unsigned char* plainText:
 *				size_t plainTextLength:
 *	@return:
 *				true: success
 *				false: error
 *	@desc:
 *				
 ***********************************************************************************************************/
bool SunGcrypt::Decrypt(const string key, unsigned char* cipherText, unsigned int cipherTextLength, unsigned char* plainText, size_t plainTextLength)
{
	unsigned int reqbufferLength = GetDecryptedLength(cipherTextLength);
	if(plainTextLength < reqbufferLength)
	{
		errMsg = "";
		cout << "SunGcrypt::Decrypt() plain text buffer is too small" << endl;
		return false;
	}

	if(!OpenAESHandle())
		return false;

	if(!SetAESKey(key))
		return false;

	if(!SetAESIV())
		return false;

	unsigned char buffer[cipherTextLength];
	memcpy(buffer, cipherText, cipherTextLength);

	errCode = gcry_cipher_decrypt(aesHandle, buffer, cipherTextLength, NULL, 0);
	if(errCode)
	{
		errMsg = "SunGcrypt::Decrypt()";
		return false;
	}

	memcpy(plainText, buffer, plainTextLength);
	CloseAESHandle();
	return true;
}

/************************************************************************************************************
 *	@params:
 *				const string key:
 *	@return:
 *				n/a
 *	@desc:
 *				displays the hexadecimal representation of the input key
 ***********************************************************************************************************/
void SunGcrypt::PrintKeyHex(const string key)
{
	cout << "Key: ";
	for(int i=0; i<key.size(); i++)
		printf(" %02X ", (unsigned char)key[i]);
	cout << endl;
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
 *				closes the handle used for AES
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
 *				const string key:
 *	@return:
 *				true: success
 *				false: error	
 *	@desc:
 *				
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
 *				
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
 *				unsigned char* ivBuffer:
 *				unsigned int ivBufferLength:
 *	@return:
 *				n/a
 *	@desc:
 *				
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
 *				const string key:
 *				unsigned char* data:
 *				unsigned int dataLength:
 *				unsigned char* signedData:
 *				unsigned int signedDataLength:
 *	@return:
 *				true: success
 *				false: error	
 *	@desc:
 *				
 ***********************************************************************************************************/
bool SunGcrypt::AppendHMAC(const string key, unsigned char* data, unsigned int dataLength, unsigned char* signedData, unsigned int signedDataLength)
{
	unsigned int hmacLength = GetHMACLength();
	if(signedDataLength < dataLength+hmacLength)
	{
		cout << "Error SunGcrypt::AppendHMAC() signed data buffer too small" << endl;
		return false;
	}

	unsigned char hmac[hmacLength];

	if(!OpenHMACHandle())
		return false;

	if(!SetHMACKey(key))
		return false;

	if(!WriteHMAC(data, dataLength))
		return false;

	if(!ReadHMAC(hmac,(size_t*)&hmacLength))
		return false;

	CloseHMACHandle();
	memcpy(signedData, data, dataLength);
	memcpy(signedData+dataLength, hmac, hmacLength);
	return true;
}

/************************************************************************************************************
 *	@params:
 *				const string key:
 *				unsigned char* signedData:
 *				unsigned int signedDataLength:
 *				unsigned char* cipherText:
 *				unsigned int cipherTextLength:
 *	@return:
 *				true: hmac valid
 *				false: hmac invalid
 *	@desc:
 *				
 ***********************************************************************************************************/
bool SunGcrypt::CheckHMAC(const string key, unsigned char* signedData, unsigned int signedDataLength, unsigned char* cipherText, unsigned int cipherTextLength)
{
	unsigned int hmacLength = GetHMACLength();
	unsigned char hmac[hmacLength];

	if(!OpenHMACHandle())
		return false;

	if(!SetHMACKey(key))
		return false;

	if(!WriteHMAC(signedData, signedDataLength-hmacLength))
		return false;

	if(!VerifyHMAC(signedData+(signedDataLength-hmacLength),hmacLength))
		return false;

	CloseHMACHandle();
	memcpy(cipherText, signedData, signedDataLength-hmacLength);
	return true;
}

/************************************************************************************************************
 *	@params:
 *				n/a
 *	@return:
 *				true: success
 *				false: error	
 *	@desc:
 *				
 ***********************************************************************************************************/
bool SunGcrypt::OpenHMACHandle()
{
	errCode = gcry_mac_open(&hmacHandle, GCRY_MAC_HMAC_SHA512, 0, NULL);
	if(errCode)
	{
		errMsg = "SunGcrypt::OpenHMACHandle()";
		return false;
	}
	return true;
}

/************************************************************************************************************
 *	@params:
 *				const string key:
 *	@return:
 *				true: success
 *				false: error	
 *	@desc:
 *				
 ***********************************************************************************************************/
bool SunGcrypt::SetHMACKey(const string key)
{
	errCode = gcry_mac_setkey(hmacHandle, key.c_str(), key.size());
	if(errCode)
	{
		errMsg = "SunGcrypt::SetHMACKey()";
		return false;
	}
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
	return gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA512);
}

/************************************************************************************************************
 *	@params:
 *				const unsigned char* dataBuffer:
 *				size_t bufferLength:
 *	@return:
 *				true: success
 *				false: error	
 *	@desc:
 *				
 ***********************************************************************************************************/
bool SunGcrypt::WriteHMAC(const unsigned char* dataBuffer, size_t bufferLength)
{
	errCode = gcry_mac_write(hmacHandle, dataBuffer, bufferLength);
	if(errCode)
	{
		errMsg = "SunGcrypt::SetHMACKey()";
		return false;
	}
	return true;
}

/************************************************************************************************************
 *	@params:
 *				unsigned char* hmacBuffer:
 *				size_t* bufferLength:
 *	@return:
 *				true: success
 *				false: error	
 *	@desc:
 *				
 ***********************************************************************************************************/
bool SunGcrypt::ReadHMAC(unsigned char* hmacBuffer, size_t* bufferLength)
{
	errCode = gcry_mac_read(hmacHandle, hmacBuffer, bufferLength);
	if(errCode)
	{
		errMsg = "SunGcrypt::ReadHMAC()";
		return false;
	}
	return true;
}

/************************************************************************************************************
 *	@params:
 *				const unsigned char* hmac:
 *				size_t hmacLength:
 *	@return:
 *				true: success
 *				false: error	
 *	@desc:
 *				
 ***********************************************************************************************************/
bool SunGcrypt::VerifyHMAC(const unsigned char* hmac, size_t hmacLength)
{
	errCode = gcry_mac_verify(hmacHandle, hmac, hmacLength);
	if(errCode)
	{
		errMsg = "SunGcrypt::VerifyHMAC() HMAC Verification Failed";
		return false;
	}
	return true;
}

/************************************************************************************************************
 *	@params:
 *				n/a
 *	@return:
 *				n/a
 *	@desc:
 *				
 ***********************************************************************************************************/
void SunGcrypt::CloseHMACHandle()
{
	gcry_mac_close(hmacHandle);
}