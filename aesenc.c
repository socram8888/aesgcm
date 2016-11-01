/*
 * Copyright (c) 2016 Marcos Vives Del Sol
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "pass.h"

#include <assert.h>
#include <stdio.h>

#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>

void mbedtls_perror(const char * message, int ret) {
	char errortxt[256];
	mbedtls_strerror(ret, errortxt, sizeof(errortxt));
	fprintf(stderr, "%s: %s\n", message, errortxt);
}

int main() {
	int ret;

    mbedtls_entropy_context entropyctx;
	uint8_t randomsalt[32];
	mbedtls_entropy_init(&entropyctx);

	ret = mbedtls_entropy_func(&entropyctx, randomsalt, sizeof(randomsalt));
	if (ret) {
		mbedtls_perror("Entropy gather failed", ret);
		mbedtls_entropy_free(&entropyctx);
		return 1;
	}
	mbedtls_entropy_free(&entropyctx);

	mbedtls_md_context_t mdctx;
	mbedtls_md_init(&mdctx);

    const mbedtls_md_info_t * mdinfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
	if (mdinfo == NULL) {
		fprintf(stderr, "SHA-512 lookup failed in mbed TLS\n");
		return 1;
	}

	ret = mbedtls_md_setup(&mdctx, mdinfo, 1);
	if (ret) {
		mbedtls_perror("HMAC context initialization failed", ret);
		mbedtls_md_free(&mdctx);
		return 1;
	}

	char pass[128];
	while (1) {
		char passverify[128];
		if (!pass_prompt("Password: ", pass, sizeof(pass))) {
			return 1;
		}

		if (!pass_prompt("Verify: ", passverify, sizeof(passverify))) {
			return 1;
		}

		if (strcmp(pass, passverify) == 0) {
			memset(passverify, 0, sizeof(passverify));
			break;
		}

		fprintf(stderr, "Passwords do not match\n");
	}

	printf("Password = \"%s\"\n", pass);

	uint8_t derivedpass[64];
	ret = mbedtls_pkcs5_pbkdf2_hmac(&mdctx, (uint8_t *) pass, strlen(pass), randomsalt, sizeof(randomsalt), 10000, sizeof(derivedpass), derivedpass);
	memset(pass, 0, sizeof(pass));
	mbedtls_md_free(&mdctx);

	if (ret) {
		mbedtls_perror("HMAC context initialization failed", ret);
		return 1;
	}

	if (fwrite(randomsalt, sizeof(randomsalt), 1, stdout) != 1) {
		perror("fwrite salt");
		return 1;
	}

	return 0;
}
