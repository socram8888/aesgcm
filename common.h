/*
 * Copyright (c) 2016 Marcos Vives Del Sol
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <stdint.h>

#include <mbedtls/gcm.h>

#define MAXPASSLEN 128
#define CHUNKSIZE 16 /* AES256 takes 128 bit chunks */

void mbedtls_perror(const char * message, int ret);

int initialize(int argc, char ** argv, char * pass);
int prepare_aes(char * pass, const uint8_t * salt, mbedtls_gcm_context * keys, int operation);
