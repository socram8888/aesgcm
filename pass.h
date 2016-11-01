/*
 * Copyright (c) 2016 Marcos Vives Del Sol
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <string.h>
#include <stdbool.h>

bool pass_prompt(const char * prompt, char * pass, size_t maxpasslen);
