/**
*  $Id: md5.h,v 1.2 2006/03/03 15:04:49 tomas Exp $
*  Cryptographic module for Lua.
*  @author  Roberto Ierusalimschy
*
*  Taken from the md5 Lua library 1.3 (https://github.com/keplerproject/md5),
*  designed and implemented by Roberto Ierusalimschy and Marcela Ozorio
*  Suarez. Copyright (c) 2003-2013 PUC-Rio, MIT licensed (see LICENSE-THIRD-PARTY).
*
*  Changes for lua-digest:
*  - no Lua dependency: lua.h include and luaopen_md5_core removed
*  - md5_t buffers a partial block, so md5_update accepts pieces of any
*    length, and counts the message length in 64 bits (two WORD32)
*  - md5_update returns nothing; md5_finish does the padding;
*    the one-shot md5() function is gone
*  - the functions are static (the file is compiled as part of digestlib.c),
*    so they cannot clash with other MD5 code in the same process
*/


#ifndef md5_h
#define md5_h

#include <stddef.h>


#define HASHSIZE       16

#define MD5_DIGEST_LENGTH	HASHSIZE
#define MD5_BLOCK_LENGTH	64

#if __STDC_VERSION__ >= 199901L
#include <stdint.h>
typedef uint32_t WORD32;
#else
/* static assert that int equal or greater than 32bit. */
typedef char static_assert_sizeof_int
    [sizeof(unsigned int) >= 4 ? 1 : -1];
typedef unsigned int WORD32;
#endif

typedef struct md5_t {
  WORD32 d[4];
  WORD32 len[2];                    /* message length in bytes: low, high word */
  char buffer[MD5_BLOCK_LENGTH];    /* pending bytes of an incomplete block */
} md5_t;

static void md5_init   (md5_t *m);
static void md5_update (md5_t *m, const char *message, size_t len);
static void md5_finish (md5_t *m, char output[HASHSIZE]);


#endif
