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

	/* create a buffer to store the plain text appened by a single block containing the IV, in order */
	/* to ensure the plain text is at least greater than 1 block in length, for CTS */
	char buffer[bufferLength];
	memcpy(buffer, plainText, plainTextLength);
	unsigned char iv[SUNGCRY_BLK_SIZE];
	GetIV(iv , SUNGCRY_BLK_SIZE);
	memcpy(buffer+plainTextLength, iv, SUNGCRY_BLK_SIZE);

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
 *				the encrypted cipher text was appended by a block containing the IV, so after decryption
 *				this block is removed, and then the result is copied into the plainText buffer
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
	memcpy(plainText, buffer, plainTextLength);
	CloseAESHandle();
	return true;
}

/************************************************************************************************************
 *	@params:
 *				const string key: string containing the key to print in hex
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

	/* create the hmacHandle */
	if(!OpenHMACHandle())
		return false;

	/* set the key for the hmacHandle */
	if(!SetHMACKey(key))
	{
		CloseHMACHandle();
		return false;
	}

	/* write the hmac for the encrypted data */
	if(!WriteHMAC(data, dataLength))
	{
		CloseHMACHandle();
		return false;
	}

	/* read the resulting hmac signature */
	if(!ReadHMAC(hmac,(size_t*)&hmacLength))
	{
		CloseHMACHandle();
		return false;
	}

	/* close the hmacHandle, copy data appended by HMAC signature to the signedData buffer */
	CloseHMACHandle();
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
	unsigned char hmac[hmacLength];

	/* create the hmacHandle */
	if(!OpenHMACHandle())
		return false;
	
	/* set the key for the hmacHandle */
	if(!SetHMACKey(key))
	{
		CloseHMACHandle();
		return false;
	}

	/* write the HMAC for the encrypted data portion of the signedData */
	if(!WriteHMAC(signedData, signedDataLength-hmacLength))
	{
		CloseHMACHandle();
		return false;
	}

	/* verify the HMAC located at the end of the signedData buffer */
	if(!VerifyHMAC(signedData+(signedDataLength-hmacLength),hmacLength))
	{
		CloseHMACHandle();
		return false;
	}

	/* close the hmacHandle, copy the encrypted data to the cipherText buffer */
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
 *				wraps the gcry_mac_open function 
 *				utilizes SHA-512 as the underlying MAC algorithm
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
 *				const string key: buffer holding the HMAC key
 *	@return:
 *				true: success
 *				false: error	
 *	@desc:
 *				wraps the gcry_mac_setkey function
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
 *				const unsigned char* dataBuffer: data to write HMAC for
 *				size_t bufferLength: length of the dataBuffer
 *	@return:
 *				true: success
 *				false: error	
 *	@desc:
 *				wraps the gcry_mac_write function
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
 *				unsigned char* hmacBuffer: buffer to hold the HMAC value for the hmacHandle
 *				size_t* bufferLength: length of the hmacBuffer
 *	@return:
 *				true: success
 *				false: error	
 *	@desc:
 *				wraps the gcry_mac_read function
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
 *				const unsigned char* hmac: buffer with the hmac to verify against the hmac for the hmacHandle
 *				size_t hmacLength: length of the hmac buffer
 *	@return:
 *				true: success
 *				false: error	
 *	@desc:
 *				wraps the gcry_mac_verify function
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
 *				wraps the gcry_mac_close function to close the hmacHandle
 ***********************************************************************************************************/
void SunGcrypt::CloseHMACHandle()
{
	gcry_mac_close(hmacHandle);
}
