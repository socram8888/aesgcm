/*
 * Copyright (c) 2016 Marcos Vives Del Sol
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "common.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char ** argv) {
	int ret;

	char password[MAXPASSLEN];

	ret = initialize(argc, argv, password);
	if (ret) {
		return ret;
	}

	uint8_t salt[CHUNKSIZE];
	if (!fread(salt, sizeof(salt), 1, stdin)) {
		perror("Failed to read random salt");
		memset(password, 0, sizeof(password));
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
