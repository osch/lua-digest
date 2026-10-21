/*
 * digest -- MD5, SHA-256, SHA-384 and SHA-512 digests and HMAC for Lua.
 *
 * Lua binding (MIT licensed, see LICENSE). The hash cores are
 * md5.c (from the md5 Lua library, PUC-Rio, MIT) and sha2.c
 * (Aaron D. Gifford, BSD-3-Clause).
 */

#include <string.h>

#include <lua.h>
#include <lauxlib.h>
/* the hash cores are part of this translation unit, so that their functions
 * can be static: the module exports nothing but luaopen_digest */
#include "md5.c"
#include "sha2.c"

/* LUA_DIGEST_VERSION comes from the rockspec (e.g. -DLUA_DIGEST_VERSION=0.1.0) */
#ifndef LUA_DIGEST_VERSION
    #error LUA_DIGEST_VERSION is not defined
#endif

#define LUA_DIGEST_TOSTRING_HELPER(x) #x
#define LUA_DIGEST_TOSTRING(x) LUA_DIGEST_TOSTRING_HELPER(x)
#define LUA_DIGEST_VERSION_STRING LUA_DIGEST_TOSTRING(LUA_DIGEST_VERSION)

#if LUA_VERSION_NUM < 502
#  define lua_rawlen lua_objlen   /* used by carray_capi.h */
#endif

/*
 * carray objects (https://github.com/osch/lua-carray) are recognized through
 * the Carray C API: no link or rockspec dependency on the carray module.
 */
#define CARRAY_CAPI_IMPLEMENT_GET_CAPI 1
#if defined(__GNUC__)
/* carray_capi.h is kept verbatim; it forward-declares enum typedefs */
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wpedantic"
#endif
#include "carray_capi.h"
#if defined(__GNUC__)
#  pragma GCC diagnostic pop
#endif

#define DIGEST_CLASS_NAME	"digest.digest"

/* the largest digest and block sizes of all algorithms */
#define MAX_DIGEST_LENGTH	SHA512_DIGEST_LENGTH
#define MAX_BLOCK_LENGTH	SHA512_BLOCK_LENGTH

/* ======================================================================== */

/*
 * Remembers the Carray C API of the last carray argument. Its
 * toReadableCarray() accepts any Lua value and returns NULL for everything
 * that is not one of its carrays, so it is tried first and the C API need not
 * be looked up in the metatable for each call. One per Lua state, an upvalue
 * of all functions that take data arguments (no static mutable state).
 */
typedef struct CapiCache {
	const carray_capi *capi;
} CapiCache;

#define CAPI_CACHE	lua_upvalueindex(1)

/* returns the carray at idx (and its C API in *capiOut), NULL if idx is no carray */
static const carray *to_carray(lua_State *L, int idx, const carray_capi **capiOut, carray_info *info) {
	CapiCache *cc = (CapiCache*)lua_touserdata(L, CAPI_CACHE);
	const carray_capi *capi = cc->capi;
	const carray *ca = NULL;

	if (lua_type(L, idx) != LUA_TUSERDATA) {
		return NULL;
	}
	ca = capi ? capi->toReadableCarray(L, idx, info) : NULL;
	if (!ca) {
		capi = carray_get_capi(L, idx, NULL);
		if (capi) {
			ca = capi->toReadableCarray(L, idx, info);
			if (ca) {
				cc->capi = capi;
			}
		}
	}
	*capiOut = ca ? capi : NULL;
	return ca;
}

/*
 * Data argument: a Lua string (or number, as luaL_checklstring) or a carray
 * with 1 byte elements, which is read directly from its buffer without
 * copying. No Lua code runs while the data is hashed, so the pointer stays
 * valid. Anything else raises the usual "string expected" argument error.
 */
static const uint8_t *check_data(lua_State *L, int arg, size_t *len) {
	if (lua_type(L, arg) == LUA_TUSERDATA) {
		const carray_capi *capi;
		carray_info info;
		const carray *ca = to_carray(L, arg, &capi, &info);
		if (ca) {
			const uint8_t *ptr;
			if (info.elementSize != 1) {
				luaL_argerror(L, arg, "carray elements must be 1 byte in size");
			}
			*len = info.elementCount;
			if (*len == 0) {
				return (const uint8_t*)"";
			}
			ptr = (const uint8_t*)capi->getReadableElementPtr(ca, 0, *len);
			if (!ptr) {
				luaL_error(L, "cannot access carray");
			}
			return ptr;
		}
	}
	return (const uint8_t*)luaL_checklstring(L, arg, len);
}

/* ======================================================================== */

/* source: md5lib.c from the md5 Lua library; data arguments may be carrays */
/**
*  X-Or. Does a bit-a-bit exclusive-or of two strings.
*  @param s1: arbitrary binary string or byte carray.
*  @param s2: arbitrary binary string or byte carray with same length as s1.
*  @return  a binary string with same length as s1 and s2,
*   where each bit is the exclusive-or of the corresponding bits in s1-s2.
*/
static int ex_or (lua_State *L) {
	size_t l1, l2;
	const char *s1 = (const char*)check_data(L, 1, &l1);
	const char *s2 = (const char*)check_data(L, 2, &l2);
	luaL_Buffer b;
	luaL_argcheck( L, l1 == l2, 2, "lengths must be equal" );
	luaL_buffinit(L, &b);
	while (l1--) luaL_addchar(&b, (*s1++)^(*s2++));
	luaL_pushresult(&b);
	return 1;
}

/* ======================================================================== */
/* algorithms                                                               */

enum { ALG_MD5, ALG_SHA256, ALG_SHA384, ALG_SHA512 };

typedef struct {
	const char *name;      /* name as accepted by new/hmac and returned by algorithm() */
	const char *label;     /* display name for __tostring */
	int bits;              /* number accepted by new/hmac in place of the name, 0: none */
	size_t digestLength;
	size_t blockLength;    /* HMAC block size */
} AlgInfo;

static const AlgInfo algs[] = {
	{"md5",    "MD5",     0,   MD5_DIGEST_LENGTH,    MD5_BLOCK_LENGTH},
	{"sha256", "SHA-256", 256, SHA256_DIGEST_LENGTH, SHA256_BLOCK_LENGTH},
	{"sha384", "SHA-384", 384, SHA384_DIGEST_LENGTH, SHA384_BLOCK_LENGTH},
	{"sha512", "SHA-512", 512, SHA512_DIGEST_LENGTH, SHA512_BLOCK_LENGTH},
};

#define NUM_ALGS	((int)(sizeof(algs) / sizeof(algs[0])))

/*
 * Algorithm argument: one of the names "md5", "sha256", "sha384", "sha512"
 * or one of the numbers 256, 384, 512 (as Perl's Digest::SHA->new(bits)).
 */
static int check_alg(lua_State *L, int arg) {
	int i;
	if (lua_type(L, arg) == LUA_TNUMBER) {
		lua_Number n = lua_tonumber(L, arg);
		for (i = 0; i < NUM_ALGS; i++) {
			if (algs[i].bits != 0 && n == (lua_Number)algs[i].bits) {
				return i;
			}
		}
	} else if (lua_type(L, arg) == LUA_TSTRING) {
		const char *s = lua_tostring(L, arg);
		for (i = 0; i < NUM_ALGS; i++) {
			if (strcmp(s, algs[i].name) == 0) {
				return i;
			}
		}
	} else {
		return luaL_argerror(L, arg, lua_pushfstring(L,
		    "algorithm name or number expected, got %s", luaL_typename(L, arg)));
	}
	return luaL_argerror(L, arg, lua_pushfstring(L,
	    "unknown algorithm '%s' (expected 'md5', 'sha256', 'sha384', 'sha512', 256, 384 or 512)",
	    lua_tostring(L, arg)));
}

/* hashing context of any of the algorithms (SHA384_CTX is SHA512_CTX) */
typedef struct {
	int alg;
	union {
		md5_t md5;
		SHA256_CTX c256;
		SHA512_CTX c512;
	} u;
} Digest;

static void digest_init(Digest *d) {
	switch (d->alg) {
		case ALG_MD5:    md5_init(&d->u.md5); break;
		case ALG_SHA256: SHA256_Init(&d->u.c256); break;
		case ALG_SHA384: SHA384_Init(&d->u.c512); break;
		default:         SHA512_Init(&d->u.c512); break;
	}
}

static void digest_update(Digest *d, const uint8_t *data, size_t len) {
	switch (d->alg) {
		case ALG_MD5:    md5_update(&d->u.md5, (const char*)data, len); break;
		case ALG_SHA256: SHA256_Update(&d->u.c256, data, len); break;
		case ALG_SHA384: SHA384_Update(&d->u.c512, data, len); break;
		default:         SHA512_Update(&d->u.c512, data, len); break;
	}
}

/* writes the binary digest to out; the context must be re-initialized to be reused */
static void digest_final(Digest *d, uint8_t *out) {
	switch (d->alg) {
		case ALG_MD5:    md5_finish(&d->u.md5, (char*)out); break;
		case ALG_SHA256: SHA256_Final(out, &d->u.c256); break;
		case ALG_SHA384: SHA384_Final(out, &d->u.c512); break;
		default:         SHA512_Final(out, &d->u.c512); break;
	}
}

/* hashes data in one go; out receives algs[alg].digestLength bytes */
static void digest_buffer(int alg, const uint8_t *data, size_t len, uint8_t *out) {
	Digest d;
	d.alg = alg;
	digest_init(&d);
	digest_update(&d, data, len);
	digest_final(&d, out);
}

static void push_digest(lua_State *L, const uint8_t *digest, size_t len, int hex) {
	if (hex) {
		static const char hexdigits[] = "0123456789abcdef";
		char buf[MAX_DIGEST_LENGTH * 2];
		size_t i;
		for (i = 0; i < len; i++) {
			buf[2*i]   = hexdigits[digest[i] >> 4];
			buf[2*i+1] = hexdigits[digest[i] & 0x0f];
		}
		lua_pushlstring(L, buf, 2 * len);
	} else {
		lua_pushlstring(L, (const char*)digest, len);
	}
}

/* ======================================================================== */
/* one-shot functions                                                       */

/* one-shot hash of the data argument 1 */
static int oneshot(lua_State *L, int alg, int hex) {
	size_t len;
	const uint8_t *data = check_data(L, 1, &len);
	uint8_t digest[MAX_DIGEST_LENGTH];
	digest_buffer(alg, data, len, digest);
	push_digest(L, digest, algs[alg].digestLength, hex);
	return 1;
}

/**
*  @param: an arbitrary binary string or byte carray.
*  @return: an MD5 hash string (16 bytes).
*/
static int md5(lua_State *L) { return oneshot(L, ALG_MD5, 0); }

/**
*  @param: an arbitrary binary string or byte carray.
*  @return: an MD5 hash as lowercase hex string.
*/
static int md5hex(lua_State *L) { return oneshot(L, ALG_MD5, 1); }

/**
*  @param: an arbitrary binary string or byte carray.
*  @return: an SHA-256 hash string.
*/
static int sha256(lua_State *L) { return oneshot(L, ALG_SHA256, 0); }

/**
*  @param: an arbitrary binary string or byte carray.
*  @return: an SHA-256 hash as lowercase hex string.
*/
static int sha256hex(lua_State *L) { return oneshot(L, ALG_SHA256, 1); }

/**
*  @param: an arbitrary binary string or byte carray.
*  @return: an SHA-384 hash string.
*/
static int sha384(lua_State *L) { return oneshot(L, ALG_SHA384, 0); }

/**
*  @param: an arbitrary binary string or byte carray.
*  @return: an SHA-384 hash as lowercase hex string.
*/
static int sha384hex(lua_State *L) { return oneshot(L, ALG_SHA384, 1); }

/**
*  @param: an arbitrary binary string or byte carray.
*  @return: an SHA-512 hash string.
*/
static int sha512(lua_State *L) { return oneshot(L, ALG_SHA512, 0); }

/**
*  @param: an arbitrary binary string or byte carray.
*  @return: an SHA-512 hash as lowercase hex string.
*/
static int sha512hex(lua_State *L) { return oneshot(L, ALG_SHA512, 1); }

/* ======================================================================== */
/* HMAC (RFC 2104)                                                          */

static int do_hmac(lua_State *L, int hex) {
	int alg = check_alg(L, 1);
	size_t keylen, len, i;
	const uint8_t *key = check_data(L, 2, &keylen);
	const uint8_t *data = check_data(L, 3, &len);
	size_t blockLength = algs[alg].blockLength;
	size_t digestLength = algs[alg].digestLength;
	uint8_t k[MAX_BLOCK_LENGTH];
	uint8_t pad[MAX_BLOCK_LENGTH];
	uint8_t inner[MAX_DIGEST_LENGTH];
	uint8_t mac[MAX_DIGEST_LENGTH];
	Digest d;

	/* keys longer than the block size are hashed, shorter ones zero-padded */
	memset(k, 0, sizeof(k));
	if (keylen > blockLength) {
		digest_buffer(alg, key, keylen, k);
	} else if (keylen > 0) {
		memcpy(k, key, keylen);
	}

	/* inner = H((K ^ ipad) || data) */
	d.alg = alg;
	for (i = 0; i < blockLength; i++) pad[i] = k[i] ^ 0x36;
	digest_init(&d);
	digest_update(&d, pad, blockLength);
	digest_update(&d, data, len);
	digest_final(&d, inner);

	/* mac = H((K ^ opad) || inner) */
	for (i = 0; i < blockLength; i++) pad[i] = k[i] ^ 0x5c;
	digest_init(&d);
	digest_update(&d, pad, blockLength);
	digest_update(&d, inner, digestLength);
	digest_final(&d, mac);

	memset(k, 0, sizeof(k));
	memset(pad, 0, sizeof(pad));
	memset(&d, 0, sizeof(d));
	push_digest(L, mac, digestLength, hex);
	return 1;
}

/**
*  digest.hmac(alg, key, data) -> binary HMAC
*  @param alg: 'md5', 'sha256', 'sha384', 'sha512' or 256, 384, 512.
*  @param key, data: binary strings or byte carrays.
*/
static int hmac(lua_State *L) { return do_hmac(L, 0); }

/**
*  digest.hmachex(alg, key, data) -> HMAC as lowercase hex string
*/
static int hmachex(lua_State *L) { return do_hmac(L, 1); }

/* ======================================================================== */
/* streaming digest objects                                                 */

static Digest *check_digest(lua_State *L, int idx) {
	return (Digest*)luaL_checkudata(L, idx, DIGEST_CLASS_NAME);
}

static Digest *new_digest(lua_State *L, int alg) {
	Digest *d = (Digest*)lua_newuserdata(L, sizeof(Digest));
	memset(d, 0, sizeof(Digest));
	d->alg = alg;
	luaL_getmetatable(L, DIGEST_CLASS_NAME);
	lua_setmetatable(L, -2);
	return d;
}

/**
*  digest.new(alg) -> digest object in its initial state
*  @param alg: 'md5', 'sha256', 'sha384', 'sha512' or 256, 384, 512.
*/
static int digest_new(lua_State *L) {
	int alg = check_alg(L, 1);
	Digest *d = new_digest(L, alg);
	digest_init(d);
	return 1;
}

/**
*  obj:add(data, ...) -> obj
*  Feeds the data arguments (strings or byte carrays) in order.
*/
static int digest_add(lua_State *L) {
	Digest *d = check_digest(L, 1);
	int i, n = lua_gettop(L);
	for (i = 2; i <= n; i++) {
		size_t len;
		const uint8_t *data = check_data(L, i, &len);
		digest_update(d, data, len);
	}
	lua_settop(L, 1);
	return 1;
}

/* finishes the hash, pushes the digest and resets the object */
static int digest_finish(lua_State *L, int hex) {
	Digest *d = check_digest(L, 1);
	uint8_t digest[MAX_DIGEST_LENGTH];
	digest_final(d, digest);
	digest_init(d);
	push_digest(L, digest, algs[d->alg].digestLength, hex);
	return 1;
}

/**
*  obj:digest() -> binary digest; the object is reset afterwards.
*/
static int digest_digest(lua_State *L) { return digest_finish(L, 0); }

/**
*  obj:hexdigest() -> lowercase hex digest; the object is reset afterwards.
*/
static int digest_hexdigest(lua_State *L) { return digest_finish(L, 1); }

/**
*  obj:reset() -> obj, back in the initial state.
*/
static int digest_reset(lua_State *L) {
	Digest *d = check_digest(L, 1);
	digest_init(d);
	lua_settop(L, 1);
	return 1;
}

/**
*  obj:clone() -> independent copy of obj with the current state.
*/
static int digest_clone(lua_State *L) {
	Digest *d = check_digest(L, 1);
	Digest *c = new_digest(L, d->alg);
	memcpy(c, d, sizeof(Digest));
	return 1;
}

/**
*  obj:algorithm() -> 'md5', 'sha256', 'sha384' or 'sha512'
*/
static int digest_algorithm(lua_State *L) {
	Digest *d = check_digest(L, 1);
	lua_pushstring(L, algs[d->alg].name);
	return 1;
}

static int digest_tostring(lua_State *L) {
	Digest *d = check_digest(L, 1);
	lua_pushfstring(L, "%s (%s): %p", DIGEST_CLASS_NAME, algs[d->alg].label, (void*)d);
	return 1;
}

/* ======================================================================== */

static void set_info (lua_State *L) {
	lua_pushliteral (L, "_VERSION");
	lua_pushliteral (L, "digest " LUA_DIGEST_VERSION_STRING);
	lua_settable (L, -3);
}

typedef struct {
	const char *name;
	lua_CFunction func;
} digest_reg;

/* module functions, each gets the CapiCache as upvalue */
static const digest_reg reg[] = {
	{"md5", md5},
	{"md5hex", md5hex},
	{"sha256", sha256},
	{"sha256hex", sha256hex},
	{"sha384", sha384},
	{"sha384hex", sha384hex},
	{"sha512", sha512},
	{"sha512hex", sha512hex},
	{"new", digest_new},
	{"hmac", hmac},
	{"hmachex", hmachex},
	{"exor", ex_or},
	{NULL, NULL}
};

/* methods of digest objects, each gets the CapiCache as upvalue */
static const digest_reg methods[] = {
	{"add", digest_add},
	{"digest", digest_digest},
	{"hexdigest", digest_hexdigest},
	{"reset", digest_reset},
	{"clone", digest_clone},
	{"algorithm", digest_algorithm},
	{NULL, NULL}
};

/* sets the functions of r into the table at the top, with upvalue cc (an absolute index) */
static void set_funcs(lua_State *L, const digest_reg *r, int cc) {
	for (; r->name; r++) {
		lua_pushstring(L, r->name);
		lua_pushvalue(L, cc);
		lua_pushcclosure(L, r->func, 1);
		lua_rawset(L, -3);
	}
}

int luaopen_digest(lua_State *L) {
	int n = 0, cc;
	CapiCache *cache = (CapiCache*)lua_newuserdata(L, sizeof(CapiCache));
	cache->capi = NULL;
	cc = lua_gettop(L);

	if (luaL_newmetatable(L, DIGEST_CLASS_NAME)) {
		lua_pushliteral(L, DIGEST_CLASS_NAME);
		lua_setfield(L, -2, "__name");
		lua_pushcfunction(L, digest_tostring);
		lua_setfield(L, -2, "__tostring");
		lua_newtable(L);
		set_funcs(L, methods, cc);
		lua_setfield(L, -2, "__index");
	}
	lua_pop(L, 1);

	while (reg[n].name) n++;
	lua_createtable(L, 0, n + 1);
	set_funcs(L, reg, cc);
	set_info (L);
	lua_remove(L, cc);
#if LUA_VERSION_NUM < 502
	lua_pushvalue(L, -1);
	lua_setglobal(L, "digest");
#endif
	return 1;
}
