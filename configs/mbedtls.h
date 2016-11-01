/*
 * Copyright (c) 2016 Marcos Vives Del Sol
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

// We'll be using AES-GCM, with AES-NI if possible.
#define MBEDTLS_AES_C
#define MBEDTLS_AESNI_C
#define MBEDTLS_GCM_C

// Padding for AES.
#define MBEDTLS_CIPHER_PADDING_PKCS7

// Entropy for random IV creation.
#define MBEDTLS_ENTROPY_C

// PBKDF2 for pre-shared key to AES key derivation.
#define MBEDTLS_MD_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_PKCS5_C

// Every modern processor has SSE2. Fuck backwards compatibility.
#define MBEDTLS_HAVE_SSE2

// Random stuff.
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_VERSION_C
#define MBEDTLS_ERROR_C

#include "mbedtls/check_config.h"

#endif
