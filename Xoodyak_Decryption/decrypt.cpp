#include "crypto_aead.h"
#include "api.h"
#include "Xoodyak.h"
#include <string.h>

#if !defined(CRYPTO_KEYBYTES)
#define CRYPTO_KEYBYTES 16
#endif
#if !defined(CRYPTO_NPUBBYTES)
#define CRYPTO_NPUBBYTES 16
#endif
# define TAGLEN 16

int crypto_aead_decrypt(
	unsigned char *m, unsigned long long *mlen,
	unsigned char *nsec,
	const unsigned char *c, unsigned long long clen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k)
{
	Xoodyak instance(BitString(k, 8 * CRYPTO_KEYBYTES), BitString(npub, 8 * CRYPTO_NPUBBYTES), BitString());
	unsigned char tag[TAGLEN];
	unsigned long long mlen_;

	(void)nsec;

	*mlen = 0;
	if (clen < TAGLEN)
	{
		return -1;
	}
	mlen_ = clen - TAGLEN;
	instance.Absorb(BitString(ad, 8 * (size_t)adlen));
	BitString decryptString = instance.Decrypt(BitString(c, 8 * (size_t)mlen_));
	if (decryptString.size() != 0)
		std::copy(decryptString.array(), decryptString.array() + (decryptString.size() + 7) / 8, m);
	BitString tagString = instance.Squeeze(TAGLEN);
	if (tagString.size() != 0)
		std::copy(tagString.array(), tagString.array() + (tagString.size() + 7) / 8, tag);
	if (memcmp(tag, c + mlen_, TAGLEN) != 0)
	{
		memset(m, 0, (size_t)mlen_);
		return -1;
	}
	*mlen = mlen_;
	return 0;
}


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *hexToChar(const char *hexString)
{
	size_t len = strlen(hexString);
	if (len % 2 != 0)
	{
		printf("Invalid hex string length\n");
		return NULL;
	}

	size_t charLen = len / 2;
	char *charString = (char *)malloc(charLen + 1);
	charString[charLen] = '\0';

	for (size_t i = 0, j = 0; i < len; i += 2, j++)
	{
		char byteString[3];
		strncpy(byteString, hexString + i, 2);
		byteString[2] = '\0';

		char byte = (char)strtol(byteString, NULL, 16);
		charString[j] = byte;
	}

	return charString;
}

int main()
{
	unsigned char plaintext[10000]; // Updated to accommodate larger input
	unsigned char ciphertext[10000 + CRYPTO_KEYBYTES];
	unsigned char decryptedtext[10000]; // Updated to accommodate larger input
	unsigned long long plaintext_len;	// Set the expected plaintext length
	unsigned long long ciphertext_len;
	// Key and nonce for encryption and decryption
	unsigned char key[CRYPTO_KEYBYTES] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
	unsigned char nonce[CRYPTO_NPUBBYTES] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};

	printf("Enter Ciphered: ");
	char inputHex[200];
	if (fgets(inputHex, sizeof(inputHex), stdin) == NULL)
	{
		printf("Error reading input.\n");
		return -1;
	}

	size_t inputLen = strlen(inputHex);

	if (inputLen > 0 && inputHex[inputLen - 1] == '\n')
		inputHex[inputLen - 1] = '\0'; // Remove newline character

	char *outputText = hexToChar(inputHex);
	ciphertext_len = strlen(outputText);

	strcpy((char *)ciphertext, outputText);
	crypto_aead_decrypt(decryptedtext, &plaintext_len, NULL, ciphertext, ciphertext_len, NULL, 0, nonce, key);

	printf("Decrypted: %s\n", (unsigned char*) decryptedtext);


	return 0;
}
