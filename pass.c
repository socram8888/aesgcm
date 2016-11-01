/*
 * Copyright (c) 2016 Marcos Vives Del Sol
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "pass.h"
#include <stdio.h>

void trimnl(char * str) {
	size_t len = strlen(str);

	while (
		len > 0 &&
		(str[len - 1] == '\r' || str[len - 1] == '\n')
	) {
		len--;
	}

	str[len] = '\0';
}

#ifdef _WIN32

#include <windows.h>

bool pass_prompt(const char * prompt, char * pass, size_t maxpasslen) {
	DWORD originalmode;

	// Try with stdin
	FILE * terminal = stdin;
	HANDLE termhandle = GetStdHandle(STD_INPUT_HANDLE);

	if (!GetConsoleMode(termhandle, &originalmode)) {
		// If stdin is not a console, open CONIN
		// Important: SetConsoleMode call *requires write permission*
		terminal = fopen("CONIN$", "r+t");
		if (terminal == NULL) {
			return false;
		}

		// Now get current active mode
		termhandle = _get_osfhandle(_fileno(terminal));
		if (!GetConsoleMode(termhandle, &originalmode)) {
			fclose(terminal);
			return false;
		}
	}

	// Disable terminal echo
	if (!SetConsoleMode(termhandle, originalmode & ~ENABLE_ECHO_INPUT)) {
		if (terminal != stdin) {
			fclose(terminal);
		}
		return false;
	}

	// Display prompt
	fputs(prompt, stderr);

	// Read password
	pass = fgets(pass, maxpasslen, terminal);

	// Restore terminal
	if (!SetConsoleMode(termhandle, originalmode)) {
		if (terminal != stdin) {
			fclose(terminal);
		}
		return false;
	}

	// We're done with the terminal, close it now
	if (terminal != stdin) {
		fclose(terminal);
	}

	// If fgets failed, abort now
	if (pass == NULL) {
		return false;
	}

	// Print new line
	fputc('\n', stderr);

	// fgets includes newline character, so we'll get rid of it
	trimnl(pass);

	return true;
}

#else

#include <termios.h>

bool pass_prompt(const char * prompt, char * pass, size_t maxpasslen) {
	bool ok = false;

	// Open terminal
	FILE * terminal = fopen("/dev/tty", "r+");
	if (!terminal) {
		return false;
	}

	// Save original terminal options
	struct termios original;
	if (tcgetattr(fileno(terminal), &original) == -1) {
		fclose(terminal);
		return false;
	}

	// Now disable echo
	struct termios noecho;
	memcpy(&original, &noecho, sizeof(original));
	noecho.c_lflag &= ~ECHO;
	if (tcsetattr(fileno(terminal), TCSAFLUSH, &noecho) == -1) {
		fclose(terminal);
		return false;
	}

	// Display prompt
	fputs(prompt, terminal);

	// Read password
	pass = fgets(pass, maxpasslen, terminal);

	// Restore original terminal options and close it
	if (tcsetattr(fileno(terminal), TCSAFLUSH, &original) == -1) {
		fclose(terminal);
		return false;
	}

	// We're done with the terminal, close it now
	fclose(terminal);

	// If fgets failed, abort now
	if (pass == NULL) {
		return false;
	}

	trimnl(pass);

	return true;
}

#endif
