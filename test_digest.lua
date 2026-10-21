--[[
	Test suite for the digest module (MD5, SHA-256, SHA-384, SHA-512):
	one-shot functions, streaming digest objects and carray data.

	Reference values:
	  testvectors/vector*.info  SHA-2 test vectors (bundled with the SHA-2 core)
	  testvectors/MD5SUMS       MD5 of the same vector*.dat files
	  testvectors/REPEAT_A      all algorithms for 'a' repeated N times
	  RFC 1321 appendix A.5     MD5 test suite

	Usage: lua test_digest.lua
	  LUA_DIGEST_TEST_REQUIRE_CARRAY=1  missing carray module is an error (CI)
	  LUA_DIGEST_TEST_HUGE=1            also stream 4 GiB + 192 KiB per algorithm
]]

local digest = require 'digest'

print(digest._VERSION)

-- name, number accepted by digest.new, one-shot functions, digest size
local algs = {
	{ name = 'md5',    info = 'MD5',    size = 16, bin = digest.md5,    hex = digest.md5hex },
	{ name = 'sha256', info = 'SHA256', size = 32, bin = digest.sha256, hex = digest.sha256hex, bits = 256 },
	{ name = 'sha384', info = 'SHA384', size = 48, bin = digest.sha384, hex = digest.sha384hex, bits = 384 },
	{ name = 'sha512', info = 'SHA512', size = 64, bin = digest.sha512, hex = digest.sha512hex, bits = 512 },
}
local byname = {}
for _, a in ipairs(algs) do
	byname[a.name] = a
end

local function bintohex(s)
	return (s:gsub('(.)', function(c)
		return string.format('%02x', string.byte(c))
	end))
end

-- carray is optional: its tests are skipped when the module is missing,
-- unless LUA_DIGEST_TEST_REQUIRE_CARRAY=1 is set (CI), which makes it an error
local has_carray, carray = pcall(require, 'carray')
if not has_carray then
	if os.getenv('LUA_DIGEST_TEST_REQUIRE_CARRAY') == '1' then
		error('carray module required (LUA_DIGEST_TEST_REQUIRE_CARRAY=1) but not loadable:\n' .. tostring(carray), 0)
	end
	carray = nil
end

local function tocarray(s, t)
	return carray.new(t or 'uint8'):append(s)
end

local npass, nfail = 0, 0

local function check(name, got, want)
	if got == want then
		npass = npass + 1
	else
		nfail = nfail + 1
		print(('%s: FAIL (%s ~= %s)'):format(name, tostring(got), tostring(want)))
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

-- deterministic pseudo random numbers (Park-Miller, exact with doubles too)
local seed = 12345
local function rand(n)
	seed = (seed * 16807) % 2147483647
	return seed % n
end

-- feeds s in chunks of size n through a new digest object
local function streamed(alg, s, n, hex)
	local d = digest.new(alg)
	for i = 1, #s, n do
		d:add(s:sub(i, i + n - 1))
	end
	if hex then
		return d:hexdigest()
	end
	return bintohex(d:digest())
end

-- feeds s in chunks of random size (0 included) through a new digest object
local function streamed_random(alg, s, maxchunk)
	local d = digest.new(alg)
	local i = 1
	while i <= #s do
		local n = rand(maxchunk + 1)
		d:add(s:sub(i, i + n - 1))
		if rand(4) == 0 then
			d:add('')
		end
		i = i + n
	end
	return d:hexdigest()
end

local function test_vector(datname, s, a, v)
	local k = a.name
	check(('%s %s bin'):format(datname, k), bintohex(a.bin(s)), v)
	check(('%s %s hex'):format(datname, k), a.hex(s), v)
	for _, n in ipairs({1, 7, 63, 64, 65, 127, 128, 1000}) do
		check(('%s %s stream %d'):format(datname, k, n), streamed(k, s, n), v)
	end
	check(('%s %s stream hex'):format(datname, k), streamed(k, s, 1000, true), v)
	check(('%s %s stream random'):format(datname, k), streamed_random(k, s, 200), v)
	if a.bits then
		check(('%s %s stream new(%d)'):format(datname, k, a.bits), streamed(a.bits, s, 100), v)
	end

	-- several arguments in one add() call
	local d = digest.new(k)
	local h = math.floor(#s / 3)
	d:add(s:sub(1, h), s:sub(h + 1, 2 * h), '', s:sub(2 * h + 1))
	check(('%s %s add(...)'):format(datname, k), d:hexdigest(), v)

	-- clone of a half-fed object
	d:add(s:sub(1, h))
	local c = d:clone()
	c:add(s:sub(h + 1))
	d:add('different tail')
	check(('%s %s clone'):format(datname, k), c:hexdigest(), v)
	check(('%s %s clone independent'):format(datname, k), d:hexdigest(),
		a.hex(s:sub(1, h) .. 'different tail'))

	if carray then
		local ca = tocarray(s)
		check(('%s %s carray bin'):format(datname, k), bintohex(a.bin(ca)), v)
		check(('%s %s carray hex'):format(datname, k), a.hex(ca), v)
		check(('%s %s carray char'):format(datname, k), a.hex(tocarray(s, 'char')), v)
		check(('%s %s carray int8'):format(datname, k), a.hex(tocarray(s, 'int8')), v)
		local d2 = digest.new(k)
		d2:add(tocarray(s:sub(1, h)), s:sub(h + 1, 2 * h), tocarray(s:sub(2 * h + 1)))
		check(('%s %s carray add'):format(datname, k), d2:hexdigest(), v)
	end
end

local function test_digest_object()
	for _, a in ipairs(algs) do
		local k = a.name
		local empty = a.hex('')
		local d = digest.new(k)
		check(k .. ' algorithm', d:algorithm(), k)
		if a.bits then
			check(k .. ' algorithm of new(bits)', digest.new(a.bits):algorithm(), k)
		end
		check(k .. ' fresh', d:hexdigest(), empty)
		check(k .. ' add returns self', d:add('abc'), d)
		local bin = d:digest()
		check(k .. ' digest', bin, a.bin('abc'))
		check(k .. ' digest size', #bin, a.size)
		check(k .. ' hex size', #a.hex('abc'), 2 * a.size)
		check(k .. ' digest resets', d:hexdigest(), empty)
		check(k .. ' add() no args', d:add(), d)
		check(k .. ' chaining', d:add('a'):add('b', 'c'):hexdigest(), a.hex('abc'))
		d:add('garbage')
		check(k .. ' reset returns self', d:reset(), d)
		check(k .. ' reset', d:hexdigest(), empty)
		d:add('ab')
		local c = d:clone()
		check(k .. ' clone algorithm', c:algorithm(), k)
		check(k .. ' clone is new object', c ~= d, true)
		c:reset()
		check(k .. ' clone reset leaves original', d:add('c'):hexdigest(), a.hex('abc'))
		local label = ({md5 = 'MD5', sha256 = 'SHA-256', sha384 = 'SHA-384', sha512 = 'SHA-512'})[k]
		check(k .. ' tostring', tostring(d):find('digest.digest (' .. label .. ')', 1, true) == 1, true)
		check(k .. ' number data', digest.new(k):add(12):hexdigest(), a.hex('12'))
		check_error(k .. ' add table', 'string expected, got table', d.add, d, {})
		check_error(k .. ' add nil', 'string expected, got nil', d.add, d, 'x', nil)
		check_error(k .. ' digest on non-object', 'digest.digest expected', d.digest, {})
		check_error(k .. '(table)', 'string expected, got table', a.bin, {})
		check_error(k .. 'hex()', 'string expected, got no value', a.hex)
	end
	for _, bad in ipairs({1, 224, 256.5, 'md4', 'SHA256', 'sha-256', '256'}) do
		check_error('new(' .. tostring(bad) .. ')', 'unknown algorithm', digest.new, bad)
	end
	check_error('new()', 'algorithm name or number expected, got no value', digest.new)
	check_error('new({})', 'algorithm name or number expected, got table', digest.new, {})
end

-- RFC 1321, appendix A.5
local function test_rfc1321()
	local suite = {
		{ '', 'd41d8cd98f00b204e9800998ecf8427e' },
		{ 'a', '0cc175b9c0f1b6a831c399e269772661' },
		{ 'abc', '900150983cd24fb0d6963f7d28e17f72' },
		{ 'message digest', 'f96b697d7cb7938d525a2f31aaf161d0' },
		{ 'abcdefghijklmnopqrstuvwxyz', 'c3fcd3d76192e4007dfb496cca67e13b' },
		{ 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
		  'd174ab98d277d9f5a5611c2c9f419d9f' },
		{ '12345678901234567890123456789012345678901234567890123456789012345678901234567890',
		  '57edf4a22be3c955ac49da2e2107b67a' },
	}
	for i, t in ipairs(suite) do
		test_vector('rfc1321.' .. i, t[1], byname.md5, t[2])
	end
end

local function test_repeat_a()
	local f = assert(io.open('testvectors/REPEAT_A', 'r'))
	local n = 0
	for line in f:lines() do
		local len, k, v = line:match('^(%d+) (%w+) (%x+)$')
		if len then
			n = n + 1
			local s = ('a'):rep(tonumber(len))
			local a = byname[k]
			check(('a*%s %s'):format(len, k), a.hex(s), v)
			check(('a*%s %s stream 1'):format(len, k), streamed(k, s, 1, true), v)
			check(('a*%s %s stream 13'):format(len, k), streamed(k, s, 13, true), v)
			check(('a*%s %s stream random'):format(len, k), streamed_random(k, s, 300), v)
		end
	end
	f:close()
	check('REPEAT_A entries', n > 0, true)
end

-- chunked feeding of every length around the block boundaries
local function test_lengths()
	local t = {}
	for i = 1, 600 do
		t[i] = string.char((i * 31 + 7) % 256)
	end
	local base = table.concat(t)
	for _, a in ipairs(algs) do
		for len = 0, 300 do
			local s = base:sub(1, len)
			local v = a.hex(s)
			local d = digest.new(a.name)
			local cut = len > 0 and rand(len + 1) or 0
			d:add(s:sub(1, cut)):add(''):add(s:sub(cut + 1))
			check(('%s len %d split %d'):format(a.name, len, cut), d:hexdigest(), v)
			if len % 17 == 0 then
				check(('%s len %d bytewise'):format(a.name, len), streamed(a.name, s, 1, true), v)
			end
		end
	end
end

local function test_carray()
	if not carray then
		print('carray module not available: carray tests skipped')
		return
	end
	for _, a in ipairs(algs) do
		local k = a.name
		check(k .. ' empty carray', a.hex(carray.new('uint8')), a.hex(''))
		check(k .. ' empty carray add', digest.new(k):add(carray.new('char')):hexdigest(), a.hex(''))
		for _, t in ipairs({'short', 'int', 'double'}) do
			check_error(k .. ' carray ' .. t, 'carray elements must be 1 byte in size',
				a.bin, carray.new(t, 4))
			check_error(k .. ' carray hex ' .. t, 'carray elements must be 1 byte in size',
				a.hex, carray.new(t, 4))
			local d = digest.new(k)
			check_error(k .. ' add carray ' .. t, 'carray elements must be 1 byte in size',
				d.add, d, 'x', carray.new(t, 4))
		end
	end
	check('exor carray', bintohex(digest.exor(tocarray('\0\255'), '\15\240')), '0f0f')
end

local function pattern_chunk()
	local chunk = {}
	for i = 0, 65535 do
		chunk[#chunk + 1] = string.char((i * 7 + 3) % 256)
	end
	return table.concat(chunk)
end

local function test_large()
	local chunk = pattern_chunk()
	local nchunks = 160            -- 160 * 64 KB = 10 MB
	local big = chunk:rep(nchunks)
	for _, a in ipairs(algs) do
		local k = a.name
		local d = digest.new(k)
		for _ = 1, nchunks do
			d:add(chunk)
		end
		check(k .. ' 10 MB stream', d:hexdigest(), a.hex(big))
		if carray then
			local ca = tocarray(chunk)
			for _ = 1, nchunks do
				d:add(ca)
			end
			check(k .. ' 10 MB carray stream', d:hexdigest(), a.hex(tocarray(big)))
		end
	end
end

-- 65539 chunks of 64 KiB (4 GiB + 192 KiB): the message length exceeds
-- 32 bits; reference digests computed with GNU coreutils over the same data
local function test_huge()
	if os.getenv('LUA_DIGEST_TEST_HUGE') ~= '1' then
		print('4 GiB tests skipped (set LUA_DIGEST_TEST_HUGE=1 to run them)')
		return
	end
	local want = {
		md5    = 'cc5bbe04ec891399bb915171b4ec16df',
		sha256 = 'e36700246b567998124cc31a023b3d5f842cb04104ac37641897b36372a3457f',
		sha384 = '6f34fb3cbeb195582172e26cd3d63c2189621b4fb80a78c0e5c62dd168217b59524bf0f3253d0571fdbb5fce859209d1',
		sha512 = 'ec69930006ef996f6eda4614b96557480678b860cfa6cdc20316dc100247ec98085f363092f5faa9f0880aee0e102d13df663894a1a9e391f21c1f9a1da886d4',
	}
	local chunk = pattern_chunk()
	for _, a in ipairs(algs) do
		local d = digest.new(a.name)
		for _ = 1, 65539 do
			d:add(chunk)
		end
		check(a.name .. ' 4 GiB stream', d:hexdigest(), want[a.name])
	end
end

local function read_info(i)
	local hashes = {}
	local g = assert(io.open(('testvectors/vector%03d.info'):format(i), 'r'))
	local name, hash
	for line in g:lines() do
		if line:find('^SHA%d+:') then
			name = line:match('^(SHA%d+)')
			hash = ''
		elseif hash then
			if #line == 0 then
				hashes[name] = hash
				hash = nil
			else
				hash = hash .. line:match('^%s*(.-)%s*$')
			end
		end
	end
	if hash then
		hashes[name] = hash
	end
	g:close()
	return hashes
end

local function read_md5sums()
	local sums = {}
	local f = assert(io.open('testvectors/MD5SUMS', 'r'))
	for line in f:lines() do
		local v, file = line:match('^(%x+)  (%S+)$')
		if v then
			sums[file] = v
		end
	end
	f:close()
	return sums
end

local function main()
	test_digest_object()
	test_rfc1321()
	test_repeat_a()
	test_lengths()
	test_carray()
	test_large()
	test_huge()

	check('exor', bintohex(digest.exor('abc', 'abc')), '000000')
	check('exor', bintohex(digest.exor('\0\255', '\15\240')), '0f0f')
	check_error('exor lengths', 'lengths must be equal', digest.exor, 'ab', 'abc')

	local md5sums = read_md5sums()
	local i, nvectors = 0, 0
	while true do
		i = i + 1
		local file = ('vector%03d.dat'):format(i)
		local datname = 'testvectors/' .. file
		local f = io.open(datname, 'rb')
		if not f then break end
		local s = f:read('*a')
		f:close()
		nvectors = nvectors + 1

		local hashes = read_info(i)
		hashes.MD5 = md5sums[file]
		for _, a in ipairs(algs) do
			local v = hashes[a.info]
			check(('%s %s reference present'):format(datname, a.name), v ~= nil, true)
			if v then
				test_vector(datname, s, a, v)
			end
		end
	end
	check('test vectors found', nvectors, 18)

	print(('%d passed, %d failed'):format(npass, nfail))
	return nfail == 0
end

local ok = main()
if type(arg) == 'table' and arg[0] and arg[0]:find('test_digest%.lua$') then
	os.exit(ok and 0 or 1)
end
return ok
