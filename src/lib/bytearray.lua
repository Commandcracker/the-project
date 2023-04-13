-- ByteArray
-- By Commandcracker
-- based on mt in [sha256](https://pastebin.com/6UV4qfNF) from [Anavrins](https://pastebin.com/u/Anavrins)
-- MIT License
-- Last updated: July 5 2022

-- Changelog:
-- [Date]        [Author]         [Change]
-- (July 5 2022) (Commandcracker) (fixed mt:sub, added mt.fromBytes and mt.fromHex)

local bxor = bit32 and bit32.bxor or bit.bxor
local bor  = bit32 and bit32.bor or bit.bor

local ByteArray

ByteArray = {
    fromBytes = function(bs)
        return setmetatable({ bs:byte(1, -1) }, ByteArray)
    end,
    fromHex = function(hex)
        local instance = {}
        for k in hex:gmatch("(%x%x)") do
            table.insert(instance, tonumber(k, 16))
        end

        return setmetatable(instance, ByteArray)
    end,
    __tostring = function(a) return string.char(unpack(a)) end,
    __index = {
        toHex = function(self, s) return ("%02x"):rep(#self):format(unpack(self)) end,
        isEqual = function(self, t)
            if type(t) ~= "table" then return false end
            if #self ~= #t then return false end
            local ret = 0
            for i = 1, #self do
                ret = bor(ret, bxor(self[i], t[i]))
            end
            return ret == 0
        end,
        sub = function(self, a, b)
            local len = #self + 1
            local start = a % len
            local stop = (b or len - 1) % len
            local ret = {}
            local i = 1
            for j = start, stop, start < stop and 1 or -1 do
                ret[i] = self[j]
                i = i + 1
            end
            return setmetatable(ret, ByteArray)
        end
    }
}

return ByteArray