-- KillaVanilla's RNG('s), composed of the Mersenne Twister RNG and the ISAAC algorithm.

-- Exposed functions:
-- initalize_mt_generator(seed) - Seed the Mersenne Twister RNG.
-- extract_mt() - Get a number from the Mersenne Twister RNG.
-- seed_from_mt(seed) - Seed the ISAAC RNG, optionally seeding the Mersenne Twister RNG beforehand.
-- generate_isaac() - Force a reseed.
-- random(min, max) - Get a random number between min and max.

-- Helper functions:
local function toBinary(a) -- Convert from an integer to an arbitrary-length table of bits
    local b = {}
    local copy = a
    while true do
        table.insert(b, copy % 2)
        copy = math.floor(copy / 2)
        if copy == 0 then
            break
        end
    end
    return b
end

local function fromBinary(a) -- Convert from an arbitrary-length table of bits (from toBinary) to an integer
    local dec = 0
    for i = #a, 1, -1 do
        dec = dec * 2 + a[i]
    end
    return dec
end

-- ISAAC internal state:
local aa, bb, cc = 0, 0, 0
local randrsl = {} -- Acts as entropy/seed-in. Fill to randrsl[256].
local mm = {}      -- Fill to mm[256]. Acts as output.

-- Mersenne Twister State:
local MT = {} -- Twister state
local index = 0

-- Other variables for the seeding mechanism
local mtSeeded = false
local mtSeed = math.random(1, 2 ^ 31 - 1)

-- The Mersenne Twister can be used as an RNG for non-cryptographic purposes.
-- Here, we're using it to seed the ISAAC algorithm, which *can* be used for cryptographic purposes.

function initalize_mt_generator(seed)
    index = 0
    MT[0] = seed
    for i = 1, 623 do
        local full = ((1812433253 * bit.bxor(MT[i - 1], bit.brshift(MT[i - 1], 30))) + i)
        local b = toBinary(full)
        while #b > 32 do
            table.remove(b, 1)
        end
        MT[i] = fromBinary(b)
    end
end

local function generate_mt() -- Restock the MT with new random numbers.
    for i = 0, 623 do
        local y = bit.band(MT[i], 0x80000000)
        y = y + bit.band(MT[(i + 1) % 624], 0x7FFFFFFF)
        MT[i] = bit.bxor(MT[(i + 397) % 624], bit.brshift(y, 1))
        if y % 2 == 1 then
            MT[i] = bit.bxor(MT[i], 0x9908B0DF)
        end
    end
end

function extract_mt(min, max) -- Get one number from the Mersenne Twister.
    if index == 0 then
        generate_mt()
    end
    local y = MT[index]
    min = min or 0
    max = max or 2 ^ 32 - 1
    --print("Accessing: MT["..index.."]...")
    y = bit.bxor(y, bit.brshift(y, 11))
    y = bit.bxor(y, bit.band(bit.blshift(y, 7), 0x9D2C5680))
    y = bit.bxor(y, bit.band(bit.blshift(y, 15), 0xEFC60000))
    y = bit.bxor(y, bit.brshift(y, 18))
    index = (index + 1) % 624
    return (y % max) + min
end

function seed_from_mt(seed) -- seed ISAAC with numbers from the MT:
    if seed then
        mtSeeded = false
        mtSeed = seed
    end
    if not mtSeeded or (math.random(1, 100) == 50) then -- Always seed the first time around. Otherwise, seed approximately once per 100 times.
        initalize_mt_generator(mtSeed)
        mtSeeded = true
        mtSeed = extract_mt()
    end
    for i = 1, 256 do
        randrsl[i] = extract_mt()
    end
end

local function mix(a, b, c, d, e, f, g, h)
    a = a % (2 ^ 32 - 1)
    b = b % (2 ^ 32 - 1)
    c = c % (2 ^ 32 - 1)
    d = d % (2 ^ 32 - 1)
    e = e % (2 ^ 32 - 1)
    f = f % (2 ^ 32 - 1)
    g = g % (2 ^ 32 - 1)
    h = h % (2 ^ 32 - 1)
    a = bit.bxor(a, bit.blshift(b, 11))
    d = (d + a) % (2 ^ 32 - 1)
    b = (b + c) % (2 ^ 32 - 1)
    b = bit.bxor(b, bit.brshift(c, 2))
    e = (e + b) % (2 ^ 32 - 1)
    c = (c + d) % (2 ^ 32 - 1)
    c = bit.bxor(c, bit.blshift(d, 8))
    f = (f + c) % (2 ^ 32 - 1)
    d = (d + e) % (2 ^ 32 - 1)
    d = bit.bxor(d, bit.brshift(e, 16))
    g = (g + d) % (2 ^ 32 - 1)
    e = (e + f) % (2 ^ 32 - 1)
    e = bit.bxor(e, bit.blshift(f, 10))
    h = (h + e) % (2 ^ 32 - 1)
    f = (f + g) % (2 ^ 32 - 1)
    f = bit.bxor(f, bit.brshift(g, 4))
    a = (a + f) % (2 ^ 32 - 1)
    g = (g + h) % (2 ^ 32 - 1)
    g = bit.bxor(g, bit.blshift(h, 8))
    b = (b + g) % (2 ^ 32 - 1)
    h = (h + a) % (2 ^ 32 - 1)
    h = bit.bxor(h, bit.brshift(a, 9))
    c = (c + h) % (2 ^ 32 - 1)
    a = (a + b) % (2 ^ 32 - 1)
    return a, b, c, d, e, f, g, h
end

local function isaac()
    local x, y = 0, 0
    for i = 1, 256 do
        x = mm[i]
        if (i % 4) == 0 then
            aa = bit.bxor(aa, bit.blshift(aa, 13))
        elseif (i % 4) == 1 then
            aa = bit.bxor(aa, bit.brshift(aa, 6))
        elseif (i % 4) == 2 then
            aa = bit.bxor(aa, bit.blshift(aa, 2))
        elseif (i % 4) == 3 then
            aa = bit.bxor(aa, bit.brshift(aa, 16))
        end
        aa = (mm[((i + 128) % 256) + 1] + aa) % (2 ^ 32 - 1)
        y = (mm[(bit.brshift(x, 2) % 256) + 1] + aa + bb) % (2 ^ 32 - 1)
        mm[i] = y
        bb = (mm[(bit.brshift(y, 10) % 256) + 1] + x) % (2 ^ 32 - 1)
        randrsl[i] = bb
    end
end

local function randinit(flag)
    local a, b, c, d, e, f, g, h = 0x9e3779b9, 0x9e3779b9, 0x9e3779b9, 0x9e3779b9, 0x9e3779b9, 0x9e3779b9, 0x9e3779b9,
        0x9e3779b9 -- 0x9e3779b9 is the golden ratio
    aa = 0
    bb = 0
    cc = 0
    for i = 1, 4 do
        a, b, c, d, e, f, g, h = mix(a, b, c, d, e, f, g, h)
    end
    for i = 1, 256, 8 do
        if flag then
            a = (a + randrsl[i]) % (2 ^ 32 - 1)
            b = (b + randrsl[i + 1]) % (2 ^ 32 - 1)
            c = (c + randrsl[i + 2]) % (2 ^ 32 - 1)
            d = (b + randrsl[i + 3]) % (2 ^ 32 - 1)
            e = (e + randrsl[i + 4]) % (2 ^ 32 - 1)
            f = (f + randrsl[i + 5]) % (2 ^ 32 - 1)
            g = (g + randrsl[i + 6]) % (2 ^ 32 - 1)
            h = (h + randrsl[i + 7]) % (2 ^ 32 - 1)
        end
        a, b, c, d, e, f, g, h = mix(a, b, c, d, e, f, g, h)
        mm[i] = a
        mm[i + 1] = b
        mm[i + 2] = c
        mm[i + 3] = d
        mm[i + 4] = e
        mm[i + 5] = f
        mm[i + 6] = g
        mm[i + 7] = h
    end

    if flag then
        for i = 1, 256, 8 do
            a = (a + randrsl[i]) % (2 ^ 32 - 1)
            b = (b + randrsl[i + 1]) % (2 ^ 32 - 1)
            c = (c + randrsl[i + 2]) % (2 ^ 32 - 1)
            d = (b + randrsl[i + 3]) % (2 ^ 32 - 1)
            e = (e + randrsl[i + 4]) % (2 ^ 32 - 1)
            f = (f + randrsl[i + 5]) % (2 ^ 32 - 1)
            g = (g + randrsl[i + 6]) % (2 ^ 32 - 1)
            h = (h + randrsl[i + 7]) % (2 ^ 32 - 1)
            a, b, c, d, e, f, g, h = mix(a, b, c, d, e, f, g, h)
            mm[i] = a
            mm[i + 1] = b
            mm[i + 2] = c
            mm[i + 3] = d
            mm[i + 4] = e
            mm[i + 5] = f
            mm[i + 6] = g
            mm[i + 7] = h
        end
    end
    isaac()
    randcnt = 256
end

function generate_isaac(entropy)
    aa = 0
    bb = 0
    cc = 0
    if entropy and #entropy >= 256 then
        for i = 1, 256 do
            randrsl[i] = entropy[i]
        end
    else
        seed_from_mt()
    end
    for i = 1, 256 do
        mm[i] = 0
    end
    randinit(true)
    isaac()
    isaac() -- run isaac twice
end

local function getRandom()
    if #mm > 0 then
        return table.remove(mm, 1)
    else
        generate_isaac()
        return table.remove(mm, 1)
    end
end

function random(min, max)
    if not max then
        max = 2 ^ 32 - 1
    end
    if not min then
        min = 0
    end
    return (getRandom() % max) + min
end

print(random(1, 20))
-----------------------------
-- random.lua - Random Byte Generator

local sha256 = require("sha256")

local entropy = ""
local accumulator = ""
local entropyPath = "/.random"

local function feed(data)
    accumulator = accumulator .. (data or "")
end

local function digest()
    entropy = tostring(sha256.digest(entropy .. accumulator))
    accumulator = ""
end

if fs.exists(entropyPath) then
    local entropyFile = fs.open(entropyPath, "rb")
    feed(entropyFile.readAll())
    entropyFile.close()
end

local t0 = os.epoch("utc")
local t1 = t0
local iterations = 1
feed("init")
feed(tostring(math.random(1, 2 ^ 31 - 1)))
feed("|")
feed(tostring(math.random(1, 2 ^ 31 - 1)))
feed("|")
feed(tostring(math.random(1, 2 ^ 4)))
feed("|")
feed(tostring(t0))
feed("|")
while (t1 - t0 < 500) or (iterations < 10000) do
    t1 = os.epoch("utc")
    local s = tostring({}):sub(8)
    while #s < 8 do
        s = "0" .. s
    end
    feed(string.char(t1 % 256))
    feed(string.char(tonumber(s:sub(1, 2), 16)))
    feed(string.char(tonumber(s:sub(3, 4), 16)))
    feed(string.char(tonumber(s:sub(5, 6), 16)))
    feed(string.char(tonumber(s:sub(7, 8), 16)))
    iterations = iterations + 1
end
digest()
feed(tostring(os.epoch("utc")))
digest()

local function save()
    feed("save")
    feed(tostring(os.epoch("utc")))
    feed(tostring({}))
    digest()

    local entropyFile = fs.open(entropyPath, "wb")
    entropyFile.write(tostring(sha256.hmac("save", entropy)))
    entropy = tostring(sha256.digest(entropy))
    entropyFile.close()
end
save()

local function seed(data)
    feed("seed")
    feed(tostring(os.epoch("utc")))
    feed(tostring({}))
    feed(data)
    digest()
    save()
end

local function random()
    feed("random")
    feed(tostring(os.epoch("utc")))
    feed(tostring({}))
    digest()
    save()

    local result = sha256.hmac("out", entropy)
    entropy = tostring(sha256.digest(entropy))

    return result
end

print(random())

return {
    seed = seed,
    save = save,
    random = random
}

-----------------------------


-- Cryptographically Secure Random Number Generator

-- CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)

-- ISAAC
