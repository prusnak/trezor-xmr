#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "keccak.h"

#include "KeccakNISTInterface.h"

int keccak(const uint8_t *in, int inlen, uint8_t *md, int mdlen)
{
	mdlen <<= 3U;
    if (mdlen != 224 && mdlen != 256 && mdlen != 384 && mdlen != 512)
    {
    	return BAD_HASHLEN;
	}

	hashState state;
	Keccak_Init(&state, mdlen);
	Keccak_Update(&state, in, inlen << 3U);
	Keccak_Final(&state, md);

	return 0;
}

