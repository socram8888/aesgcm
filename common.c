/*
 * Copyright (c) 2016 Marcos Vives Del Sol
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "common.h"
#include "pass.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

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

int initialize(int argc, char ** argv, char * password) {

#ifdef _WIN32
	_setmode(_fileno(stdout), _O_BINARY);
	_setmode(_fileno(stdin), _O_BINARY);
#endif

	int ret;
	password[0] = '\0';

	int c;
	while ((c = getopt(argc, argv, "k:")) != -1) {
		switch (c) {
			case 'k':
				strncpy(password, optarg, MAXPASSLEN - 1);
				password[MAXPASSLEN - 1] = '\0';
				break;

			default:
				fprintf(stderr, "Unknown option \"%c\"", c);
				return 1;
		}
	}

	if (password[0] == '\0') {
		ret = ask_for_password(password);
		if (ret) {
			return ret;
		}
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
