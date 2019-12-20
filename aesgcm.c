/*
 * Copyright (c) 2016-2019 Marcos Vives Del Sol
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "pass.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#define MAXPASSLEN 128
#define CHUNKSIZE 16 /* AES256 takes 128 bit chunks */

#pragma pack(push, 1)
struct aes256_key_pair {
	uint8_t key[32];
	uint8_t iv[16];
};
#pragma pack(pop)

void mbedtls_perror(const char * message, int ret) {
	char errortxt[256];
	mbedtls_strerror(ret, errortxt, sizeof(errortxt));
	fprintf(stderr, "%s: %s\n", message, errortxt);
}

int ask_for_password(char * password) {
	while (1) {
		do {
			if (!pass_prompt("Password: ", password, MAXPASSLEN)) {
				return 1;
			}
		} while (strlen(password) == 0);

		char passverify[MAXPASSLEN];
		if (!pass_prompt("Verify: ", passverify, MAXPASSLEN)) {
			return 1;
		}

		if (strcmp(password, passverify) == 0) {
			memset(passverify, 0, MAXPASSLEN);
			break;
		}

		fprintf(stderr, "Passwords do not match\n");
	}

	return 0;
}

int derive_keys(const char * pass, const uint8_t * salt, struct aes256_key_pair * keys) {
	const mbedtls_md_info_t * mdinfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
	if (mdinfo == NULL) {
		fprintf(stderr, "SHA-512 lookup failed in mbed TLS\n");
		return 1;
	}

	mbedtls_md_context_t mdctx;
	mbedtls_md_init(&mdctx);

	int ret = mbedtls_md_setup(&mdctx, mdinfo, 1);
	if (ret) {
		mbedtls_perror("HMAC context initialization failed", ret);
		mbedtls_md_free(&mdctx);
		return 1;
	}

	ret = mbedtls_pkcs5_pbkdf2_hmac(
		&mdctx, // Context
		(uint8_t *) pass, strlen(pass), // Password
		salt, CHUNKSIZE, // Salt
		100000, // Number of iterations
		sizeof(*keys), (uint8_t *) keys // Generated keys
	);

	mbedtls_md_free(&mdctx);

	if (ret) {
		mbedtls_perror("HMAC context initialization failed", ret);
		return 1;
	}

	return 0;
}

int prepare_aes(char * pass, const uint8_t * salt, mbedtls_gcm_context * aesgcm, int operation) {
	struct aes256_key_pair keypair;
	int ret = derive_keys(pass, salt, &keypair);

	// We no longer need the password - clear it ASAP
	memset(pass, 0, MAXPASSLEN);

	if (ret) {
		return ret;
	}

	mbedtls_gcm_init(aesgcm);

	ret = mbedtls_gcm_setkey(
		aesgcm,
		MBEDTLS_CIPHER_ID_AES,
		keypair.key,
		sizeof(keypair.key) * 8
	);

	if (ret) {
		mbedtls_perror("Failed to initialize AES GCM context", ret);
		memset(&keypair, 0, sizeof(keypair));
		return 1;
	}

	ret = mbedtls_gcm_starts(
		aesgcm,
		operation,
		keypair.iv,
		sizeof(keypair.iv),
		NULL, 0
	);

	// We no longer need the keypair either - nuke it too
	memset(&keypair, 0, sizeof(keypair));

	if (ret) {
		mbedtls_perror("Failed to start AES GCM operation", ret);
		return 1;
	}

	return 0;
}

int generate_random_salt(uint8_t * salt) {
	int ret;

	mbedtls_entropy_context entropyctx;
	mbedtls_entropy_init(&entropyctx);

	ret = mbedtls_entropy_func(&entropyctx, salt, CHUNKSIZE);
	if (ret) {
		mbedtls_perror("Entropy gather failed", ret);
		mbedtls_entropy_free(&entropyctx);
		return 1;
	}
	mbedtls_entropy_free(&entropyctx);

	return 0;
}

int do_encrypt(char * password) {
	int ret;

	uint8_t salt[CHUNKSIZE];
	ret = generate_random_salt(salt);
	if (ret) {
		return ret;
	}

	mbedtls_gcm_context aesgcm;
	ret = prepare_aes(password, salt, &aesgcm, MBEDTLS_GCM_ENCRYPT);
	if (ret) {
		return ret;
	}

	if (fwrite(salt, CHUNKSIZE, 1, stdout) != 1) {
		perror("Failed to write random seed");
		mbedtls_gcm_free(&aesgcm);
		return 1;
	}

	size_t readbytes;
	do {
		uint8_t plain[CHUNKSIZE];
		uint8_t cipher[CHUNKSIZE];

		readbytes = fread(plain, 1, CHUNKSIZE, stdin);
		if (readbytes < CHUNKSIZE && !feof(stdin)) {
			perror("Failed to read plaintext");
			mbedtls_gcm_free(&aesgcm);
			return 1;
		}

		ret = mbedtls_gcm_update(&aesgcm, readbytes, plain, cipher);
		if (ret) {
			mbedtls_perror("Failed to execute AES encryption", ret);
			mbedtls_gcm_free(&aesgcm);
			return 1;
		}

		if (fwrite(cipher, 1, readbytes, stdout) != readbytes) {
			perror("Failed to write ciphertext");
			mbedtls_gcm_free(&aesgcm);
			return 1;
		}
	} while (readbytes == CHUNKSIZE);

	uint8_t tag[CHUNKSIZE];
	ret = mbedtls_gcm_finish(&aesgcm, tag, sizeof(tag));
	mbedtls_gcm_free(&aesgcm);
	if (ret) {
		mbedtls_perror("Failed to finish GCM", ret);
		return 1;
	}

	if (fwrite(tag, sizeof(tag), 1, stdout) == 0) {
		perror("Failed to write tail chunk");
	}

	return 0;
}

int do_decrypt(char * password) {
	int ret;

	uint8_t salt[CHUNKSIZE];
	if (!fread(salt, sizeof(salt), 1, stdin)) {
		perror("Failed to read random salt");
		memset(password, 0, MAXPASSLEN);
		return 1;
	}

	mbedtls_gcm_context aesgcm;
	ret = prepare_aes(password, salt, &aesgcm, MBEDTLS_GCM_DECRYPT);
	if (ret) {
		return ret;
	}

	size_t readbytes;
	uint8_t inbuffer[CHUNKSIZE * 2];

	if (!fread(inbuffer, CHUNKSIZE, 1, stdin)) {
		perror("Failed to read first chunk");
		mbedtls_gcm_free(&aesgcm);
		return 1;
	}

	do {
		uint8_t plain[CHUNKSIZE];

		readbytes = fread(inbuffer + CHUNKSIZE, 1, CHUNKSIZE, stdin);
		if (readbytes < CHUNKSIZE && !feof(stdin)) {
			perror("Failed to read ciphertext");
			mbedtls_gcm_free(&aesgcm);
			return 1;
		}

		ret = mbedtls_gcm_update(&aesgcm, readbytes, inbuffer, plain);
		if (ret) {
			mbedtls_perror("Failed to execute AES decryption", ret);
			mbedtls_gcm_free(&aesgcm);
			return 1;
		}

		if (fwrite(plain, 1, readbytes, stdout) != readbytes) {
			perror("Failed to write plaintext");
			mbedtls_gcm_free(&aesgcm);
			return 1;
		}

		memmove(inbuffer, inbuffer + readbytes, CHUNKSIZE);
	} while (readbytes == CHUNKSIZE);

	uint8_t tag[CHUNKSIZE];
	ret = mbedtls_gcm_finish(&aesgcm, tag, sizeof(tag));
	mbedtls_gcm_free(&aesgcm);
	if (ret) {
		mbedtls_perror("Failed to finish GCM", ret);
		return 1;
	}

	uint8_t different = 0;
	for (size_t i = 0; i < sizeof(tag); i++) {
		different |= tag[i] ^ inbuffer[i];
	}

	if (different) {
		fprintf(stderr, "Signature comparison failed\n");
		return 2;
	}

	return 0;
}

void show_help(const char * self) {
	fprintf(stderr,
			"Usage: %s -ed? -k (password)\n"
			"\n"
			"    -e: encryption (default)\n"
			"    -d: decryption\n"
			"    -?: show this help and quit\n"
			"    -k pass: use specified password. If this option is not specified,\n"
			"             an interactive terminal for password input will be used.\n"
			"\n"
	, self);
}

int main(int argc, char ** argv) {

#ifdef _WIN32
	_setmode(_fileno(stdout), _O_BINARY);
	_setmode(_fileno(stdin), _O_BINARY);
#endif

	int ret;
	char password[MAXPASSLEN];
	password[0] = '\0';

	int c;
	bool decrypt = false;
	while ((c = getopt(argc, argv, "?edk:")) != -1) {
		switch (c) {
			case 'e':
				decrypt = false;
				break;

			case 'd':
				decrypt = true;
				break;

			case 'k':
				strncpy(password, optarg, MAXPASSLEN - 1);
				password[MAXPASSLEN - 1] = '\0';
				break;

			case '?':
				show_help(argv[0]);
				return 0;

			default:
				show_help(argv[0]);
				return 1;
		}
	}

	if (password[0] == '\0') {
		ret = ask_for_password(password);
		if (ret) {
			return ret;
		}
	}

	if (decrypt) {
		return do_decrypt(password);
	} else {
		return do_encrypt(password);
	}
}
