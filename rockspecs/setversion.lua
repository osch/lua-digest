#!/usr/bin/lua
--[[
    Sets the release version of the versioned rockspec:

        cd rockspecs && lua setversion.lua 0.1.0

    An existing digest-X.Y.Z-N.rockspec is renamed and its version line
    updated. Without one, digest-X.Y.Z-1.rockspec is generated from
    digest-scm-0.rockspec (version line and release source archive).
]]

os.setlocale("C")

local format = string.format
local lfs    = require("lfs")

local version = ...
assert(version and version:match("^%d+%.%d+%.%d+$"), format("invalid version %q", tostring(version)))

local function readLines(fileName)
    local lines = {}
    local inFile = assert(io.open(fileName, "r"))
    for line in inFile:lines() do
        lines[#lines+1] = line
    end
    inFile:close()
    return lines
end

local function writeLines(fileName, lines)
    local newFile, err = io.open(fileName, "w")
    assert(newFile, err)
    newFile:write(table.concat(lines, "\n").."\n")
    newFile:close()
end

local found = false

for fileName in lfs.dir(".") do
    local p1, v, p2 = fileName:match("^(digest%-)(%d+%.%d+%.%d+)(%-%d+%.rockspec)$")
    if p1 then
        found = true
        local newName = p1..version..p2
        print(format("%-30s -> %s", fileName, newName))
        local out = {}
        local matched = false
        for _, line in ipairs(readLines(fileName)) do
            local l1, l2 = line:match("^(%s*version%s*%=%s*\")%d+%.%d+%.%d+(%-%d+\"%s*)$")
            if l1 then
                assert(not matched)
                matched = true
                out[#out+1] = l1..version..l2
            else
                out[#out+1] = line
            end
        end
        assert(matched)
        writeLines(newName, out)
        if fileName ~= newName then
            os.remove(fileName)
        end
    end
end

if not found then
    local newName = "digest-"..version.."-1.rockspec"
    print(format("%-30s -> %s", "digest-scm-0.rockspec", newName))
    local out = {}
    local nversion, nurl, ndir = 0, 0, 0
    for _, line in ipairs(readLines("digest-scm-0.rockspec")) do
        if line:match("^%s*version%s*=%s*\"scm%-0\"%s*$") then
            nversion = nversion + 1
            out[#out+1] = 'version = "'..version..'-1"'
            out[#out+1] = 'local versionNumber = version:gsub("^(.*)-.-$", "%1")'
        elseif line:match("^%s*url%s*=%s*\".*/archive/master%.zip\",%s*$") then
            nurl = nurl + 1
            out[#out+1] = '  url = "https://github.com/osch/lua-digest/archive/v"..versionNumber..".zip",'
        elseif line:match("^%s*dir%s*=%s*\"lua%-digest%-master\",%s*$") then
            ndir = ndir + 1
            out[#out+1] = '  dir = "lua-digest-"..versionNumber,'
        else
            out[#out+1] = line
        end
    end
    assert(nversion == 1 and nurl == 1 and ndir == 1, "unexpected layout of digest-scm-0.rockspec")
    writeLines(newName, out)
end
