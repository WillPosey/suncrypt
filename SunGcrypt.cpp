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
	handleOpen = false;
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
	if(!OpenHandle())
		return false;

	if(!SetKey(key))
		return false;

	if(!SetIV())
		return false;

	cout << endl << "PLAIN TEXT:" << endl << plainText << endl;

	errCode = gcry_cipher_encrypt(handle, cipherText, cipherTextLength, plainText, plainTextLength);

	if(errCode)
	{
		errMsg = "SunGcrypt::Encrypt()";
		return false;
	}

	CloseHandle();
	return true;
}

/****************************************************************************
 *
 ***************************************************************************/
bool SunGcrypt::Decrypt(const string key, unsigned char* cipherText, size_t cipherTextLength , unsigned char* plainText, size_t plainTextLength)
{

	if(!OpenHandle())
		return false;

	if(!SetKey(key))
		return false;

	if(!SetIV())
		return false;

	errCode = gcry_cipher_decrypt(handle, plainText, plainTextLength, cipherText, cipherTextLength);

	if(errCode)
	{
		errMsg = "SunGcrypt::Decrypt()";
		return false;
	}

	cout << endl << "PLAIN TEXT:" << endl << plainText << endl;

	CloseHandle();
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
bool SunGcrypt::OpenHandle()
{
	if(!handleOpen)
	{
		errCode = gcry_cipher_open(&handle, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);

		if(errCode)
		{
			errMsg = "SunGcrypt::OpenHandle()";
			return false;
		}
		return true;
	}
	return true;
}

/****************************************************************************
 *
 ***************************************************************************/
void SunGcrypt::CloseHandle()
{
	if(handleOpen)
	{
		gcry_cipher_close(handle);
		handleOpen = false;
	}
}

/****************************************************************************
 *
 ***************************************************************************/
bool SunGcrypt::SetKey(const string key)
{
	errCode = gcry_cipher_setkey(handle, key.c_str(), key.size());

	if(errCode)
    {
    	errMsg = "SunGcrypt::SetKey()";
    	return false;
    }

    return true;
}

/****************************************************************************
 *
 ***************************************************************************/
bool SunGcrypt::SetIV()
{
	unsigned char iv[SUNGCRY_BLK_SIZE];
	uint16_t ivVal = SUNGCRY_IV;
	memcpy(iv, &ivVal, sizeof(ivVal));

	errCode = gcry_cipher_setiv(handle, iv, SUNGCRY_BLK_SIZE);

	if(errCode)
    {
    	errMsg = "SunGcrypt::SetIV()";
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