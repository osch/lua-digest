--[[
	Runs all test suites. Used by `luarocks test` and CI:
	    lua run_tests.lua
]]

local failed = false

for _, script in ipairs({'test_digest.lua', 'test_hmac.lua'}) do
	print('')
	print('==> running ' .. script)
	if dofile(script) == false then
		failed = true
	end
end

print('')
if failed then
	print('TESTS FAILED')
	os.exit(1)
end
print('All tests passed')
