local bit = require("bit")

local function uint32_to_be(n)
	return string.char(
		bit.brshift(bit.band(n, 0xff000000), 24),
		bit.brshift(bit.band(n, 0x00ff0000), 16),
		bit.brshift(bit.band(n, 0x0000ff00), 8),
		bit.band(n, 0x000000ff)
	)
end

local function be_to_uint32(b)
	local a, b, c, d = string.byte(b, 1, 4)
	return bit.bor(bit.blshift(a, 24), bit.blshift(b, 16), bit.blshift(c, 8), d)
end

local function ch(x, y, z)
	return bit.bxor(bit.band(x, y), bit.band(bit.bnot(x), z))
end

local function maj(x, y, z)
	return bit.bxor(bit.band(x, y), bit.band(x, z), bit.band(y, z))
end

local function rotr(x, n)
	return bit.bor(bit.brshift(x, n), bit.blshift(x, 32 - n))
end

local function sigma0(x)
	return bit.bxor(rotr(x, 2), rotr(x, 13), rotr(x, 22))
end

local function sigma1(x)
	return bit.bxor(rotr(x, 6), rotr(x, 11), rotr(x, 25))
end

local function gamma0(x)
	return bit.bxor(rotr(x, 7), rotr(x, 18), bit.brshift(x, 3))
end

local function gamma1(x)
	return bit.bxor(rotr(x, 17), rotr(x, 19), bit.brshift(x, 10))
end

local function pad_message(message)
	local ml = #message * 8
	message = message .. "\x80"
	while (#message + 8) % 64 ~= 0 do
		message = message .. "\0"
	end
	message = message .. uint32_to_be(0) .. uint32_to_be(ml)
	return message
end

local function sha256(message)
	message = pad_message(message)
	local H = {
		0x6a09e667,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x510e527f,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19,
	}
	local K = {
		0x428a2f98,
		0x71374491,
		0xb5c0fbcf,
		0xe9b5dba5,
		0x3956c25b,
		0x59f111f1,
		0x923f82a4,
		0xab1c5ed5,
		0xd807aa98,
		0x12835b01,
		0x243185be,
		0x550c7dc3,
		0x72be5d74,
		0x80deb1fe,
		0x9bdc06a7,
		0xc19bf174,
		0xe49b69c1,
		0xefbe4786,
		0x0fc19dc6,
		0x240ca1cc,
		0x2de92c6f,
		0x4a7484aa,
	}
	for i = 1, #message, 64 do
		local block = message:sub(i, i + 63)
		local words = {}
		for j = 1, 16 do
			words[j] = be_to_uint32(block:sub((j - 1) * 4 + 1, j * 4))
		end
		for j = 17, 64 do
			local s0 = sigma0(words[j - 15])
			local s1 = sigma1(words[j - 2])
			words[j] = (words[j - 16] + s0 + words[j - 7] + s1) % 2 ^ 32
		end
		local a, b, c, d, e, f, g, h = table.unpack(H)
		for j = 1, 64 do
			local S1 = gamma1(e)
			local ch = ch(e, f, g)
			local temp1 = (h + S1 + ch + K[j] + words[j]) % 2 ^ 32
			local S0 = gamma0(a)
			local maj = maj(a, b, c)
			local temp2 = (S0 + maj) % 2 ^ 32
			h, g, f, e, d, c, b, a = g, f, e, (d + temp1) % 2 ^ 32, c, b, a, temp1 + temp2
		end
		H[1] = (H[1] + a) % 2 ^ 32
		H[2] = (H[2] + b) % 2 ^ 32
		H[3] = (H[3] + c) % 2 ^ 32
		H[4] = (H[4] + d) % 2 ^ 32
		H[5] = (H[5] + e) % 2 ^ 32
		H[6] = (H[6] + f) % 2 ^ 32
		H[7] = (H[7] + g) % 2 ^ 32
		H[8] = (H[8] + h) % 2 ^ 32
	end
	local digest = ""
	for i = 1, 8 do
		digest = digest .. uint32_to_be(H[i])
	end
	return digest
end

return sha256
