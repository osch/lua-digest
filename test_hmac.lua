--[[
	Test suite for digest.hmac / digest.hmachex.
	Checks HMAC-MD5 against the RFC 2202 test cases, HMAC-SHA256/384/512
	against the RFC 4231 test cases, an AWS signature example including
	base64 output, and all algorithms against a plain Lua HMAC built from
	the one-shot digest functions for keys and data of many lengths.

	Usage: lua test_hmac.lua
	  LUA_DIGEST_TEST_REQUIRE_CARRAY=1  missing carray module is an error (CI)
]]

local digest = require 'digest'

local function bintohex(s)
	return (s:gsub('(.)', function(c)
		return string.format('%02x', string.byte(c))
	end))
end

local function hextobin(s)
	return (s:gsub('(%x%x)', function(hex)
		return string.char(tonumber(hex, 16))
	end))
end

local has_carray, carray = pcall(require, 'carray')
if not has_carray then
	if os.getenv('LUA_DIGEST_TEST_REQUIRE_CARRAY') == '1' then
		error('carray module required (LUA_DIGEST_TEST_REQUIRE_CARRAY=1) but not loadable:\n' .. tostring(carray), 0)
	end
	carray = nil
end

local function tocarray(s)
	return carray.new('uint8'):append(s)
end

local npass, nfail = 0, 0

local function check(name, got, want)
	if got == want then
		npass = npass + 1
	else
		nfail = nfail + 1
		print(('%s: FAIL (%s ~= %s)'):format(name, bintohex(tostring(got)), bintohex(tostring(want))))
	end
end

local function check_error(name, pattern, f, ...)
	local ok, err = pcall(f, ...)
	if not ok and tostring(err):find(pattern, 1, true) then
		npass = npass + 1
	else
		nfail = nfail + 1
		print(('%s: FAIL (expected error "%s", got %s)'):format(name, pattern,
			ok and 'no error' or tostring(err)))
	end
end

-- base64 encoder (no luasocket dependency)
local function base64(data)
	local chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
	local out = {}
	for i = 1, #data, 3 do
		local a, b, c = data:byte(i, i + 2)
		local n = a * 65536 + (b or 0) * 256 + (c or 0)
		local q = {}
		q[1] = chars:sub(math.floor(n / 262144) % 64 + 1, math.floor(n / 262144) % 64 + 1)
		q[2] = chars:sub(math.floor(n / 4096) % 64 + 1, math.floor(n / 4096) % 64 + 1)
		q[3] = b and chars:sub(math.floor(n / 64) % 64 + 1, math.floor(n / 64) % 64 + 1) or '='
		q[4] = c and chars:sub(n % 64 + 1, n % 64 + 1) or '='
		out[#out+1] = table.concat(q)
	end
	return table.concat(out)
end

-- reference HMAC in plain Lua (RFC 2104) over the one-shot functions
local function lua_hmac(hash, blocksize, key, message)
	if #key > blocksize then
		key = hash(key) --keys longer than blocksize are shortened
	end
	key = key .. string.rep('\0', blocksize - #key) --keys shorter than blocksize are zero-padded
	local opad = digest.exor(key, string.rep(string.char(0x5c), blocksize))
	local ipad = digest.exor(key, string.rep(string.char(0x36), blocksize))
	return hash(opad .. hash(ipad .. message))
end

local function test_rfc2202()
	--per http://tools.ietf.org/html/rfc2202 (HMAC-MD5)
	local tests = {
		{ key = (hextobin'0b'):rep(16),
			data = 'Hi There',
			mac = '9294727a3638bb1c13f48ef8158bfc9d' },
		{ key = 'Jefe',
			data = 'what do ya want for nothing?',
			mac = '750c783e6ab0b503eaa86e310a5db738' },
		{ key = (hextobin'aa'):rep(16),
			data = (hextobin'dd'):rep(50),
			mac = '56be34521d144c88dbb8c733f0e8b3f6' },
		{ key = hextobin'0102030405060708090a0b0c0d0e0f10111213141516171819',
			data = (hextobin'cd'):rep(50),
			mac = '697eaf0aca3a3aea3a75164746ffaa79' },
		{ key = (hextobin'0c'):rep(16),
			data = 'Test With Truncation',
			mac = '56461ef2342edc00f9bab995690efd4c' },
		{ key = (hextobin'aa'):rep(80),
			data = 'Test Using Larger Than Block-Size Key - Hash Key First',
			mac = '6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd' },
		{ key = (hextobin'aa'):rep(80),
			data = 'Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data',
			mac = '6f630fad67cda0ee1fb1f562db3aa53e' },
	}
	for k, t in ipairs(tests) do
		check(('rfc2202.%d md5'):format(k), digest.hmac('md5', t.key, t.data), hextobin(t.mac))
		check(('rfc2202.%d md5 hex'):format(k), digest.hmachex('md5', t.key, t.data), t.mac)
	end
end

local function test_rfc4231()
	--per http://tools.ietf.org/html/rfc4231
	local tests = {
		{ key = (hextobin'0b'):rep(20),
			data = 'Hi There',
			hmac256 = 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
			hmac384 = 'afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6',
			hmac512 = '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
		},
		{ key = 'Jefe',
			data = 'what do ya want for nothing?',
			hmac256 = '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
			hmac384 = 'af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649',
			hmac512 = '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
		},
		{ key = (hextobin'aa'):rep(20),
			data = (hextobin'dd'):rep(50),
			hmac256 = '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
			hmac384 = '88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27',
			hmac512 = 'fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb',
		},
		{ key = hextobin'0102030405060708090a0b0c0d0e0f10111213141516171819',
			data = (hextobin'cd'):rep(50),
			hmac256 = '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b',
			hmac384 = '3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb',
			hmac512 = 'b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd',
		},
		-- test case 5: output truncated to 128 bits
		{ key = (hextobin'0c'):rep(20),
			data = 'Test With Truncation',
			truncate = 16,
			hmac256 = 'a3b6167473100ee06e0c796c2955552b',
			hmac384 = '3abf34c3503b2a23a46efc619baef897',
			hmac512 = '415fad6271580a531d4179bc891d87a6',
		},
		{ key = (hextobin'aa'):rep(131),
			data = 'Test Using Larger Than Block-Size Key - Hash Key First',
			hmac256 = '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
			hmac384 = '4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952',
			hmac512 = '80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598',
		},
		{ key = (hextobin'aa'):rep(131),
			data = 'This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.',
			hmac256 = '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2',
			hmac384 = '6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e',
			hmac512 = 'e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58',
		},
	}

	for k, t in ipairs(tests) do
		local n = k   -- RFC 4231 test case number
		for _, bits in ipairs({256, 384, 512}) do
			local want = t['hmac' .. bits]
			local mac = digest.hmac('sha' .. bits, t.key, t.data)
			local hex = digest.hmachex('sha' .. bits, t.key, t.data)
			if t.truncate then
				mac = mac:sub(1, t.truncate)
				hex = hex:sub(1, 2 * t.truncate)
			end
			check(('rfc4231.%d sha%d'):format(n, bits), mac, hextobin(want))
			check(('rfc4231.%d sha%d hex'):format(n, bits), hex, want)
			-- the algorithm may be given as a number as well
			local mac2 = digest.hmac(bits, t.key, t.data)
			if t.truncate then
				mac2 = mac2:sub(1, t.truncate)
			end
			check(('rfc4231.%d %d'):format(n, bits), mac2, hextobin(want))
		end
	end
end

local function test_aws()
	--per amazon aws example
	local message = 'GET\nwebservices.amazon.com\n/onca/xml\nAWSAccessKeyId=00000000000000000000&ItemId=0679722769&Operation=ItemLookup&ResponseGroup=ItemAttributes%2COffers%2CImages%2CReviews&Service=AWSECommerceService&Timestamp=2009-01-01T12%3A00%3A00Z&Version=2009-01-06'
	local mac = hextobin'35a71ef94dc0cf83a137bb484aa82cd6f74b0470448a359c05e0aa2f9c4df718'
	local key = '1234567890' --their dummy key
	local b64_mac = 'Nace+U3Az4OhN7tISqgs1vdLBHBEijWcBeCqL5xN9xg='

	check('amazon hmac256', digest.hmac('sha256', key, message), mac)
	check('amazon base64', base64(digest.hmac('sha256', key, message)), b64_mac)
end

-- all algorithms against the Lua reference, key lengths around the block sizes
local function test_reference()
	local algs = {
		{ 'md5',    digest.md5,    64 },
		{ 'sha256', digest.sha256, 64 },
		{ 'sha384', digest.sha384, 128 },
		{ 'sha512', digest.sha512, 128 },
	}
	local t = {}
	for i = 1, 400 do
		t[i] = string.char((i * 13 + 5) % 256)
	end
	local base = table.concat(t)
	for _, a in ipairs(algs) do
		local name, hash, blocksize = a[1], a[2], a[3]
		for _, keylen in ipairs({0, 1, 20, 63, 64, 65, 127, 128, 129, 200}) do
			for _, datalen in ipairs({0, 1, 55, 56, 64, 111, 112, 128, 300}) do
				local key = base:sub(1, keylen)
				local data = base:sub(401 - datalen)
				local want = lua_hmac(hash, blocksize, key, data)
				local label = ('%s key %d data %d'):format(name, keylen, datalen)
				check(label, digest.hmac(name, key, data), want)
				check(label .. ' hex', digest.hmachex(name, key, data), bintohex(want))
				if carray then
					check(label .. ' carray key', digest.hmac(name, tocarray(key), data), want)
					check(label .. ' carray data', digest.hmac(name, key, tocarray(data)), want)
					check(label .. ' carray both', digest.hmac(name, tocarray(key), tocarray(data)), want)
				end
			end
		end
	end
end

local function test_errors()
	check_error('hmac unknown alg', 'unknown algorithm', digest.hmac, 'sha1', 'k', 'd')
	check_error('hmac alg 160', 'unknown algorithm', digest.hmac, 160, 'k', 'd')
	check_error('hmac no alg', 'algorithm name or number expected', digest.hmac)
	check_error('hmac no key', 'string expected, got no value', digest.hmac, 'md5')
	check_error('hmac no data', 'string expected, got no value', digest.hmachex, 'md5', 'k')
	check_error('hmac table key', 'string expected, got table', digest.hmac, 'sha256', {}, 'd')
	check('hmac number data', digest.hmac('sha256', 'k', 12), digest.hmac('sha256', 'k', '12'))
	if carray then
		check_error('hmac carray short', 'carray elements must be 1 byte in size',
			digest.hmac, 'md5', carray.new('short', 2), 'd')
	end
end

local function main()
	test_rfc2202()
	test_rfc4231()
	test_aws()
	test_reference()
	test_errors()
	if not carray then
		print('carray module not available: carray tests skipped')
	end

	print(('%d passed, %d failed'):format(npass, nfail))
	return nfail == 0
end

local ok = main()
if type(arg) == 'table' and arg[0] and arg[0]:find('test_hmac%.lua$') then
	os.exit(ok and 0 or 1)
end
return ok
