#ifndef CRYPTO_DEFS_H
#define CRYPTO_DEFS_H

#define FILE_EXT		".uf"	/* File extension of encrypted file */
#define PBKDF2_KEY_SIZE	16		/* Size of the key returned by PBKDF2 */
#define AES_KEY_SIZE	16		/* Key length for AES (in bytes) */
#define AES_BLK_SIZE	16		/* Block size for AES (in bytes) */
#define HMAC_KEY_SIZE	16		/* Key length for HMAC (in bytes) */
#define SHA512_ITER		4096	/* Number of iterations to use for SHA-512 */
#define SALT            "NaCl"	/* Salt used for SHA-512 */
#define SALT_LENGTH		4		/* Length of the salt */

#endif //CRYPTO_DEFS_H