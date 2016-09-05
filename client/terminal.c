// Copyright (c) 2016, The Monero Project
//
// Author: NoodleDoodle
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#if defined(_WIN32)
#include <io.h>
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
int getch(void)
{
	struct termios tty_old;
	tcgetattr(STDIN_FILENO, &tty_old);

	struct termios tty_new;
	tty_new = tty_old;
	tty_new.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &tty_new);

	int ch = getchar();

	tcsetattr(STDIN_FILENO, TCSANOW, &tty_old);

	return ch;
}
#endif

size_t read_console(bool password, char *buffer, size_t maxlen)
{
	const int key_backspace = 0x08;
	const int key_delete = 0x7f;

	memset(buffer, 0, maxlen);
	ssize_t password_size = 0;
	while (password_size < maxlen - 1)
	{
		int ch = getch();
		if (ch == EOF)
		{
			return -1;
		}
		else if (ch == '\n' || ch == '\r')
		{
			printf("\n");
			break;
		}
		else if (ch == key_backspace || ch == key_delete)
		{
			if (password_size > 0)
			{
				--password_size;
				buffer[password_size] = '\0';
				printf("\b \b");
			}
		}
		else
		{
			if(!iscntrl(ch))
			{
				buffer[password_size++] = ch;
				if(!password)
					printf("%c", ch);
				else
					printf("*");
			}
		}
	}

	return password_size;
}
