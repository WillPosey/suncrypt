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

/****************************************************************************
 *
 ***************************************************************************/
SunGcrypt::SunGcrypt()
{
	gcry_check_version(NULL);
	aesHandleOpen = false;
}

/****************************************************************************
 *
 ***************************************************************************/
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

/****************************************************************************
 *
 ***************************************************************************/
bool SunGcrypt::Encrypt(const string key, unsigned char* plainText, size_t plainTextLength, unsigned char* cipherText, size_t cipherTextLength)
{
	if(!OpenAESHandle())
		return false;

	if(!SetAESKey(key))
		return false;

	if(!SetAESIV())
		return false;

	cout << endl << "PLAIN TEXT:" << endl << string((char*)plainText,plainTextLength) << endl;

	errCode = gcry_cipher_encrypt(aesHandle, cipherText, cipherTextLength, plainText, plainTextLength);

	if(errCode)
	{
		errMsg = "SunGcrypt::Encrypt()";
		return false;
	}

	CloseAESHandle();
	return true;
}

/****************************************************************************
 *
 ***************************************************************************/
bool SunGcrypt::Decrypt(const string key, unsigned char* cipherText, size_t cipherTextLength , unsigned char* plainText, size_t plainTextLength)
{

	if(!OpenAESHandle())
		return false;

	if(!SetAESKey(key))
		return false;

	if(!SetAESIV())
		return false;

	errCode = gcry_cipher_decrypt(aesHandle, plainText, plainTextLength, cipherText, cipherTextLength);

	if(errCode)
	{
		errMsg = "SunGcrypt::Decrypt()";
		return false;
	}

	cout << endl << "PLAIN TEXT:" << endl << string((char*)plainText, plainTextLength) << endl;

	CloseAESHandle();
	return true;
}

/****************************************************************************
 *
 ***************************************************************************/
void SunGcrypt::PrintKeyHex(const string key)
{
	cout << "Key: ";
	for(int i=0; i<key.size(); i++)
		printf(" %02X ", (unsigned char)key[i]);
	cout << endl;
}

/****************************************************************************
 *
 ***************************************************************************/
void SunGcrypt::PrintError()
{
	cout << errMsg << ": [source] " << gcry_strsource(errCode) << " [error] " << gcry_strerror(errCode) << endl;
}

/****************************************************************************
 *
 ***************************************************************************/
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

/****************************************************************************
 *
 ***************************************************************************/
void SunGcrypt::CloseAESHandle()
{
	if(aesHandleOpen)
	{
		gcry_cipher_close(aesHandle);
		aesHandleOpen = false;
	}
}

/****************************************************************************
 *
 ***************************************************************************/
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

/****************************************************************************
 *
 ***************************************************************************/
bool SunGcrypt::SetAESIV()
{
	unsigned char iv[SUNGCRY_BLK_SIZE];
	uint16_t ivVal = SUNGCRY_IV;
	memcpy(iv, &ivVal, sizeof(ivVal));

	errCode = gcry_cipher_setiv(aesHandle, iv, SUNGCRY_BLK_SIZE);

	if(errCode)
    {
    	errMsg = "SunGcrypt::SetAESIV()";
    	return false;
    }
	return true;
}

/****************************************************************************
 *
 ***************************************************************************/
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

/****************************************************************************
 *
 ***************************************************************************/
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

/****************************************************************************
 *
 ***************************************************************************/
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

/****************************************************************************
 *
 ***************************************************************************/
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

/****************************************************************************
 *
 ***************************************************************************/
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

/****************************************************************************
 *
 ***************************************************************************/
unsigned int SunGcrypt::GetHMACLength()
{
	return gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA512);
}

/****************************************************************************
 *
 ***************************************************************************/
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

/****************************************************************************
 *
 ***************************************************************************/
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

/****************************************************************************
 *
 ***************************************************************************/
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

/****************************************************************************
 *
 ***************************************************************************/
void SunGcrypt::CloseHMACHandle()
{
	gcry_mac_close(hmacHandle);
}