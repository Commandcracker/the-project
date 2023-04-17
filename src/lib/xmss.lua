-- DataStructure

local XMSSPrivateKey = {
	wots_private_keys = nil,
	idx = nil,
	SK_PRF = nil,
	root_value = nil,
	SEED = nil,
}

local XMSSPublicKey = {
	OID = nil,
	root_value = nil,
	SEED = nil,
}

local XMSSKeypair = {}

function XMSSPrivateKey:init(SK, PK)
	self.SK = SK
	self.PK = PK
end

local SigXMSS = {}

function SigXMSS:init(idx_sig, r, sig, SK, M2)
	self.idx_sig = idx_sig
	self.r = r
	self.sig = sig
	self.SK = SK
	self.M2 = M2
end

local SigWithAuthPath = {}

function SigWithAuthPath:init(sig_ots, auth)
	self.sig_ots = sig_ots
	self.auth = auth
end

local ADRS = {
	layerAddress = "", -- bytes(4)
	treeAddress = "", -- bytes(8)
	type = "", -- bytes(4)

	first_word = "", -- bytes(4)
	second_word = "", -- bytes(4)
	third_word = "", -- bytes(4)

	keyAndMask = "", -- bytes(4)
}

function ADRS:setType(type_value)
	self.type = string.char(type_value:byte(1, 4))
	self.first_word = ""
	self.second_word = ""
	self.third_word = ""
	self.keyAndMask = ""
end

function ADRS:getTreeHeight()
	return self.second_word
end

function ADRS:getTreeIndex()
	return self.third_word
end

function ADRS:setHashAddress(value)
	self.third_word = string.char(value:byte(1, 4))
end

function ADRS:setKeyAndMask(value)
	self.keyAndMask = string.char(value:byte(1, 4))
end

function ADRS:setChainAddress(value)
	self.second_word = string.char(value:byte(1, 4))
end

function ADRS:setTreeHeight(value)
	self.second_word = string.char(value:byte(1, 4))
end

function ADRS:setTreeIndex(value)
	self.third_word = string.char(value:byte(1, 4))
end

function ADRS:setOTSAddress(value)
	self.first_word = string.char(value:byte(1, 4))
end

function ADRS:setLTreeAddress(value)
	self.first_word = string.char(value:byte(1, 4))
end

function ADRS:setLayerAddress(value)
	self.layerAddress = string.char(value:byte(1, 4))
end

function ADRS:setTreeAddress(value)
	self.treeAddress = string.char(value:byte(1, 8))
end

-- utils.py

local function base_w(byte_string, w, out_len)
	local in_ = 0
	local total_ = 0
	local bits_ = 0
	local base_w_ = {}

	for i = 0, out_len - 1 do
		if bits_ == 0 then
			total_ = byte_string:byte(in_ + 1)
			in_ = in_ + 1
			bits_ = 8
		end
		bits_ = bits_ - math.log(w, 2)
		base_w_[i + 1] = bit32.rshift(total_, bits_) % w
	end
	return base_w_
end

local ascii_letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
local digits = 0123456789

local function generate_random_value(n)
	local alphabet = ascii_letters .. digits
	local value = ""
	for i = 1, n do
		value = value .. alphabet:sub(math.random(1, #alphabet), math.random(1, #alphabet))
	end
	return value
end

local function compute_needed_bytes(n)
	if n == 0 then
		return 1
	end
	return math.floor(math.log(n, 256)) + 1
end

local function compute_lengths(n, w)
	local len_1 = math.ceil(8 * n / math.log(w, 2))
	local len_2 = math.floor(math.log(len_1 * (w - 1), w)) + 1
	local len_all = len_1 + len_2
	return len_1, len_2, len_all
end

-- FIXME: !!
function to_byte(value, bytes_count)
	return value:to_bytes(bytes_count, byteorder='big')
end

local function xor(one, two)
	local bytearray = {}

	for a, b in ipairs(one, two) do
		table.insert(bytearray, bit32.bxor(a, b))
	end
	
	return bytearray
end

-- FIXME: !!
--[[
function int_to_bytes(val, count)
	byteVal = to_byte(val, count)
	acc = bytearray()
	for i = 1, #byteVal do
		if byteVal:byte(i) < 16 then
			acc:extend("0")
		end
		curr = string.format("%x", byteVal:byte(i))
		acc:extend(curr)
	end
	return acc
end
]]

-- FIXME: !!
--[[
function F(KEY, M)
	key_len = #KEY 
	toBytes = to_byte(0, 4)
	help_ = sha256(toBytes .. KEY .. M):sub(1, key_len)
	out = bytearray()
	out:extend(help_:byte(1, -1))
	return out
end
]]

function chain(X, i, s, SEED, address, w)
	if s == 0 then
		return X
	end
	if i + s > w - 1 then
		return nil
	end
	tmp = chain(X, i, s - 1, SEED, address, w)


	address:setHashAddress(i + s - 1)
	address:setKeyAndMask(0)
	KEY = PRF(SEED, address)
	address:setKeyAndMask(1)
	BM = PRF(SEED, address)
	tmp = F(KEY, xor(tmp, BM))
	return tmp
end

-- Rest of the functions...

-- https://github.com/lothar1998/XMSS-tree/blob/master/XMSS.py

local xmss = {}

-- Hash function (SHA-256)
local sha256 = require("sha256")

-- Bitwise left bit shift (<<)
local function left_shift(n, b)
	return bit32.lshift(n, b)
end

-- Bitwise right bit shift (>>)
local function right_shift(n, b)
	return bit32.rshift(n, b)
end

-- Convert a byte string to an integer
local function bytes_to_int(bytes)
	local result = 0
	for i = 1, #bytes do
		result = left_shift(result, 8) + string.byte(bytes, i)
	end
	return result
end

-- Convert an integer to a byte string
local function int_to_bytes(n, len)
	local bytes = {}
	for i = len, 1, -1 do
		bytes[i] = string.char(bit32.band(n, 0xFF))
		n = right_shift(n, 8)
	end
	return table.concat(bytes)
end

-- Generate a random n-byte string
local function random_bytes(n)
	local bytes = {}
	for i = 1, n do
		bytes[i] = string.char(math.random(0, 255))
	end
	return table.concat(bytes)
end

-- Generate a key pair
function xmss.keygen(n, h, w)
	local sk = {}
	sk.seed = random_bytes(n)
	sk.idx = 0
	sk.tree = {}
	for i = 0, 2 ^ h - 1 do
		sk.tree[i] = random_bytes(n)
	end
	local pk = {}
	pk.root = sk.tree[0]
	return sk, pk
end

-- Hash a message
function xmss.hash(msg)
	return sha256(msg)
end

-- Calculate the WOTS+ checksum
function xmss.wots_checksum(msg, len)
	local sum = 0
	for i = 1, len do
		sum = sum + (len + 1 - i) * string.byte(msg, i)
	end
	sum = sum * (2 ^ ((w - 1) * 8))
	return int_to_bytes(sum, n)
end

-- Generate a WOTS+ key pair
function xmss.wots_keygen(seed, idx)
	local sk = {}
	sk.seed = seed
	sk.idx = idx
	local pk = {}
	pk.chain = {}
	local c = xmss.hash(int_to_bytes(sk.idx, 4) .. sk.seed)
	local len = math.floor((n * 8 + w - 1) / w)
	for i = 1, len do
		local j = bit32.band(bit32.rshift(c, (w - 1) * 8), 2 ^ w - 1)
		pk.chain[i] = xmss.wots_chain(sk.seed, sk.idx, i - 1, j)
		c = xmss.hash(int_to_bytes(j, 2) .. pk.chain[i])
	end
	pk.pubkey = table.concat(pk.chain)
	return sk, pk
end

-- Generate a WOTS+ chain
function xmss.wots_chain(seed, idx, i, j)
	local x = xmss.hash(int_to_bytes(j, 2) .. seed .. int_to_bytes(i, 2) .. int_to_bytes(idx, 4))
	local len = math.floor((n * 8 + w - 1) / w)
	local y = {}
	for k = 1, len do
		y[k] = x
	end
	for k = 0, 2 ^ w - 2 do
		local c = 0
		for l = 1, len do
			local b = bit32.band(bit32.rshift(k, (l - 1) * w), 2 ^ w - 1)
			c = c + xmss.hash(int_to_bytes(b, 2) .. y[l])
		end
		local t = {}
		for l = 1, len do
			local b = bit32.band(bit32.rshift(k, (l - 1) * w), 2 ^ w - 1)
			local s = bit32.band(bit32.rshift(c, (l - 1) * w), 2 ^ w - 1)
			t[l] = xmss.hash(int_to_bytes(b, 2) .. y[l] .. int_to_bytes(s, 4))
		end
		y = t
	end
	return y[len]
end

-- Generate a Merkle tree
function xmss.treehash(sk, start, end_)
	if start == end_ then
		return sk.tree[start]
	end
	local mid = math.floor((start + end_) / 2)
	local left = xmss.treehash(sk, start, mid)
	local right = xmss.treehash(sk, mid + 1, end_)
	sk.tree[mid + 1] = xmss.hash(left .. right)
	return sk.tree[mid + 1]
end

-- Generate a signature
function xmss.sign(msg, sk)
	local sig = {}
	sig.wots_sigs = {}
	sig.authpath = {}
	local idx = sk.idx
	local len = math.floor((n * 8 + w - 1) / w)
	local c = xmss.hash(int_to_bytes(idx, 4) .. sk.seed)
	for i = 0, len - 1 do
		local j = bit32.band(bit32.rshift(c, (w - 1) * 8), 2 ^ w - 1)
		sig.wots_sigs[i + 1] = xmss.wots_sign(sk.seed, idx, i, j, msg)
		c = xmss.hash(int_to_bytes(j, 2) .. sig.wots_sigs[i + 1])
	end
	for i = 0, h - 1 do
		sig.authpath[i + 1] = xmss.treehash(sk, 2 ^ i, 2 ^ (i + 1) - 1)
	end
	sk.idx = sk.idx + 1
	return sig
end

-- Generate a WOTS+ signature
function xmss.wots_sign(seed, idx, i, j, msg)
	local x = xmss.wots_chain(seed, idx, i, j)
	local len = math.floor((n * 8 + w - 1) / w)
	local y = {}
	for k = 1, len do
		y[k] = x
	end
	local c = xmss.wots_checksum(x, len)
	for k = 1, len do
		local b = bit32.band(bit32.rshift(c, (k - 1) * 8), 0xFF)
		y[k] = xmss.wots_chain(seed, idx, i, b)
	end
	return int_to_bytes(j, 2) .. table.concat(y) .. xmss.wots_checksum(table.concat(y), len) .. msg
end

-- Verify a signature
function xmss.verify(msg, sig, pk)
	local len = math.floor((n * 8 + w - 1) / w)
	local c = xmss.hash(int_to_bytes(pk.root, n) .. msg)
	for i = 0, len - 1 do
		local j = bit32.band(bit32.rshift(c, (w - 1) * 8), 2 ^ w - 1)
		local y = xmss.wots_chain(sig.wots_sigs[i + 1], sig.authpath[h - i], 0, j)
		c = xmss.hash(int_to_bytes(j, 2) .. y)
	end
	return pk.root == c
end

return xmss
]]
