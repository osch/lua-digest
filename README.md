# digest — MD5, SHA-2 and HMAC for Lua

[![Tests](https://github.com/osch/lua-digest/actions/workflows/ci.yml/badge.svg)](https://github.com/osch/lua-digest/actions/workflows/ci.yml)
[![LuaRocks](https://img.shields.io/luarocks/v/osch/digest?logo=lua&color=blue)](https://luarocks.org/modules/osch/digest)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Message digests for Lua in a single C module: [MD5](https://tools.ietf.org/html/rfc1321),
[SHA-256, SHA-384 and SHA-512](https://en.wikipedia.org/wiki/SHA-2) as binary or
lowercase hex strings, in one call or through streaming digest objects, and
[HMAC](https://tools.ietf.org/html/rfc2104) for all of them. Data may be Lua strings or
[carray](https://github.com/osch/lua-carray) objects.

Works with **Lua 5.1, 5.2, 5.3, 5.4, 5.5** and **LuaJIT**.

## Features

* `md5`, `sha256`, `sha384`, `sha512` — binary digests
* `md5hex`, `sha256hex`, `sha384hex`, `sha512hex` — lowercase hex digests
* `digest.new(alg)` — streaming digest objects (`add`, `digest`, `hexdigest`,
  `reset`, `clone`), modelled on the object interface of Perl's `Digest::MD5`
  and `Digest::SHA`
* `hmac`, `hmachex` — HMAC (RFC 2104) over any of the four algorithms, in C
* Optional [carray](https://github.com/osch/lua-carray) support: byte carrays are
  hashed directly from their buffer, without copying
* `exor` — bytewise XOR helper for two equal-length binary strings
* No runtime dependencies beyond Lua itself (carray is recognized when present,
  but neither linked nor required); no global mutable state, safe to use from
  several Lua states in parallel

## Installation

```sh
luarocks install digest
```

The development version can be installed directly from its rockspec:

```sh
luarocks install https://raw.githubusercontent.com/osch/lua-digest/master/rockspecs/digest-scm-0.rockspec
```

Or from a git checkout:

```sh
git clone https://github.com/osch/lua-digest.git
cd lua-digest
luarocks make rockspecs/digest-scm-0.rockspec
```

## Usage

```lua
local digest = require "digest"

-- binary digest
local bin = digest.sha256("Hello")

-- lowercase hex digest
print(digest.md5hex("The quick brown fox jumps over the lazy dog"))
-- 9e107d9d372bb6826bd81d3542a419d6
print(digest.sha256hex("And so we say goodbye to our beloved pet, Nibbler, who's gone to a place where I, too, hope one day to go. The toilet."))
-- 3c4ba860b4917a85b075f5e0c8cebe65bd1646d0d5ac3326a974ae965a44a5e1
```

Streaming, for data that arrives in pieces:

```lua
local d = digest.new("sha256")       -- "md5", "sha256", "sha384", "sha512" or 256, 384, 512
d:add("Hello, "):add("wor", "ld")    -- add() takes several arguments and returns d
local copy = d:clone()               -- independent copy of the current state
print(d:hexdigest())                 -- same as digest.sha256hex("Hello, world"); d is reset
copy:add("!")
print(copy:hexdigest())              -- same as digest.sha256hex("Hello, world!")

-- hashing a file in 64 KB chunks
local f = assert(io.open("big.iso", "rb"))
local md5 = digest.new("md5")
for chunk in function() return f:read(65536) end do
	md5:add(chunk)
end
f:close()
print(md5:hexdigest())
```

HMAC:

```lua
print(digest.hmachex("sha256", "Jefe", "what do ya want for nothing?"))
-- 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
print(digest.hmachex("md5", "Jefe", "what do ya want for nothing?"))
-- 750c783e6ab0b503eaa86e310a5db738
local mac = digest.hmac(512, key, message)   -- binary, 64 bytes
```

carray objects (optional, needs the `carray` rock):

```lua
local carray = require "carray"
local buf = carray.new("uint8"):append("Hello")
assert(digest.sha256(buf) == digest.sha256("Hello"))   -- read in place, no string copy
digest.new("md5"):add(buf, " ", buf)                   -- strings and carrays can be mixed
```

## API

### Module functions

| Function | Description |
|---|---|
| `digest.md5(data)` | MD5 digest as a 16-byte binary string |
| `digest.sha256(data)` | SHA-256 digest as a 32-byte binary string |
| `digest.sha384(data)` | SHA-384 digest as a 48-byte binary string |
| `digest.sha512(data)` | SHA-512 digest as a 64-byte binary string |
| `digest.md5hex(data)` | MD5 digest as a 32-char lowercase hex string |
| `digest.sha256hex(data)` | SHA-256 digest as a 64-char lowercase hex string |
| `digest.sha384hex(data)` | SHA-384 digest as a 96-char lowercase hex string |
| `digest.sha512hex(data)` | SHA-512 digest as a 128-char lowercase hex string |
| `digest.new(alg)` | new digest object in its initial state |
| `digest.hmac(alg, key, data)` | HMAC of *data* with *key* as binary string |
| `digest.hmachex(alg, key, data)` | the same as lowercase hex string |
| `digest.exor(a, b)` | bytewise XOR of two equal-length binary strings |
| `digest._VERSION` | module version string, e.g. `"digest 0.1.0"` |

*alg* is one of the names `"md5"`, `"sha256"`, `"sha384"`, `"sha512"` or, as with
Perl's `Digest::SHA->new(bits)`, one of the numbers `256`, `384`, `512` (the
number and the name are equivalent). Anything else raises an error.

HMAC follows RFC 2104 with the block size of the hash function (64 bytes for
MD5 and SHA-256, 128 bytes for SHA-384 and SHA-512): longer keys are hashed
first, shorter ones zero-padded.

### Digest object methods

| Method | Description |
|---|---|
| `d:add(data, ...)` | feeds the arguments in order; returns `d`, so calls can be chained |
| `d:digest()` | binary digest of everything added so far; **resets** `d` to the initial state |
| `d:hexdigest()` | the same as lowercase hex string; also resets `d` |
| `d:reset()` | back to the initial state; returns `d` |
| `d:clone()` | independent copy of `d` with its current state |
| `d:algorithm()` | the algorithm name: `"md5"`, `"sha256"`, `"sha384"` or `"sha512"` |

`digest()`/`hexdigest()` reset the object like Perl's `Digest::MD5` and
`Digest::SHA`: to get an intermediate digest and keep adding, call
`d:clone():digest()`. `tostring(d)` gives `digest.digest (SHA-256): 0x...`.
The data may be fed in pieces of any size; the message length is counted in
64 bits, so streams beyond 4 GiB are hashed correctly.

### Data arguments

Every *data* argument (of the one-shot functions, of `add`, *key* and *data*
of `hmac`/`hmachex`, and the arguments of `exor`) is

* a Lua string (or a number, converted as by the string library), or
* a [carray](https://github.com/osch/lua-carray) with elements of 1 byte size
  (element types `char`, `uchar`, `schar`, `int8`, `uint8`; read-only carrays are
  accepted). It is read directly from its buffer, without copying. Other element
  types raise the error `carray elements must be 1 byte in size`.

carray objects are recognized through the
[Carray C API](https://github.com/lua-capis/lua-carray-capi): digest neither links
against the carray module nor requires it. Without it, a non-string argument
raises the usual `string expected` error.

## Migrating from the `sha2` and `hmac` modules

This project grew out of [lua-sha2](https://github.com/osch/lua-sha2), which
provided the Lua modules `sha2`, `hmac`, `hmac.sha2` and `hmac.md5` (the latter
on top of the [`md5`](https://luarocks.org/modules/tomasguisasola/md5) rock).
Those module names are gone; everything is now in the single C module `digest`,
including MD5 and HMAC:

| lua-sha2 | digest |
|---|---|
| `require "sha2"` | `require "digest"` |
| `sha2.sha256(s)`, `sha2.sha256hex(s)` (same for 384, 512) | `digest.sha256(s)`, `digest.sha256hex(s)` |
| `sha2.new(256)` | `digest.new(256)` or `digest.new("sha256")` |
| `d:algorithm()` → `256` | `d:algorithm()` → `"sha256"` |
| `tostring(d)` → `sha2.digest (SHA-256): ...` | `digest.digest (SHA-256): ...` |
| `sha2.exor(a, b)` | `digest.exor(a, b)` |
| `require "hmac.sha2"`; `hmac.sha256(message, key)` | `digest.hmac("sha256", key, message)` (note the argument order) |
| `require "hmac.md5"`; `hmac.md5(message, key)` | `digest.hmac("md5", key, message)` |
| `hmac.compute(key, message, hash_fn, block_size)`, `hmac.new(...)` | `digest.hmac(alg, key, message)` for the four built-in algorithms; a generic HMAC over arbitrary Lua hash functions is no longer included |
| `md5.sum(s)` / `md5.sumhexa(s)` (md5 rock) | `digest.md5(s)` / `digest.md5hex(s)` |

The `md5` rock is not needed anymore.

## Testing

The repository bundles the SHA-2 test vectors of the SHA-2 core (`testvectors/`,
with their MD5 digests in `testvectors/MD5SUMS` and digests of repeated
input around the padding boundaries in `testvectors/REPEAT_A`, both computed
with GNU coreutils), the MD5 test suite of RFC 1321 and the HMAC test cases of
RFC 2202 (HMAC-MD5) and RFC 4231 (HMAC-SHA-2). Run either way:

```sh
lua run_tests.lua    # runs both suites
# or
luarocks test rockspecs/digest-scm-0.rockspec
```

Individual suites: `lua test_digest.lua` and `lua test_hmac.lua`. Both skip their
carray tests when the `carray` rock is not installed; with
`LUA_DIGEST_TEST_REQUIRE_CARRAY=1` a missing or unloadable `carray` module is an error
instead (CI sets it, so the carray tests always run there). `LUA_DIGEST_TEST_HUGE=1`
additionally streams 4 GiB + 192 KiB through each algorithm to check the
64-bit length counters (takes about a minute).

CI runs on every push: Lua 5.1–5.5, LuaJIT and OpenResty's LuaJIT on Linux,
plus Lua 5.5 on macOS and on Windows (MSVC and MinGW gcc) and a strict-warnings
build — see [.github/workflows/ci.yml](.github/workflows/ci.yml).

## History & credits

digest continues [lua-sha2](https://github.com/osch/lua-sha2), the Lua SHA-2
binding originally published in 2010 on
[Google Code](https://code.google.com/archive/p/sha2/) by Cosmin Apreutesei, who
holds the copyright of the Lua binding (MIT licensed, see [LICENSE](LICENSE)).
lua-sha2 revived the formerly orphaned project (Lua 5.1–5.5 and LuaJIT, CI,
streaming digest objects, carray support); digest adds MD5 and HMAC in C and
merges everything into one module.

The C cores come from other projects (license texts in [LICENSE-THIRD-PARTY](LICENSE-THIRD-PARTY)):

* MD5: [`md5.c`](md5.c) / [`md5.h`](md5.h) are taken from the
  [md5 Lua library](https://github.com/keplerproject/md5) 1.3 by Roberto
  Ierusalimschy and Marcela Ozório Suarez, Copyright © 2003-2013 PUC-Rio,
  MIT licensed. Its compression function is used unchanged; the update
  function was rewritten to accept pieces of any length and to count the
  message length in 64 bits (see the file headers).
* SHA-2: [`sha2.c`](sha2.c) / [`sha2.h`](sha2.h) are by Aaron D. Gifford,
  BSD-3-Clause licensed; changed to avoid misaligned word access on input data,
  without the unused `SHA*_End`/`SHA*_Data` hex helpers.

Both cores are compiled as part of [`digestlib.c`](digestlib.c), a single
translation unit, and all their functions are `static`: the shared library
exports no symbol besides `luaopen_digest`, so it cannot clash with, or be
interposed by, other MD5/SHA-2 code in the same process (e.g. OpenSSL's
`SHA256_Init`).
* [`carray_capi.h`](carray_capi.h) is copied unchanged from the
  [Carray C API](https://github.com/lua-capis/lua-carray-capi) (header of the
  [lua-carray](https://github.com/osch/lua-carray) module), MIT licensed.
