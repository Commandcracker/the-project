-- Slogan: CC network encryption made easie
-- netnet is a lib that allows encrypting and signing rednet messages
-- netnet allows emulating the rednet API to add encrypting to any existing program that uses rednet
-- The name netnet might change


local chacha20 = require("lib.chacha20")
local ByteArray = require("lib.bytearray")
local sha256 = require("lib.sha256")
local random = math.random

local function getNonceFromEpoch()
  local nonce = {}
  local epoch = os.epoch("utc")
  for i = 1, 7 do
    nonce[#nonce + 1] = epoch % 256
    epoch = epoch / 256
    epoch = epoch - epoch % 1
  end
  for i = 8, 12 do
    nonce[i] = math.random(0, 255)
  end

  return nonce
end

-- Little utility function for easy nonce generation
local function gen_nonce(size)
  local n = {}
  for i = 1, size do n[#n + 1] = random(0, 255) end
  return n
end

local function genNonce(len)
  local nonce = {}
  for i = 1, len do
    nonce[i] = math.random(0, 0xFF)
  end
  return setmetatable(nonce, ByteArray)
end

print(setmetatable(gen_nonce(20), ByteArray))
print(setmetatable(getNonceFromEpoch(), ByteArray))
print(genNonce(20))

error(2)
-------------------------

local key = sha256.digest("453ewrdsffd342fdgdfg") -- Generate your own random key

local function encrypt(msg)
  local nonce = gen_nonce(12)
  local ctx = chacha20.crypt(msg, key, nonce)
  return { nonce, ctx }
end

local function decrypt(msg)
  local nonce = msg[1]
  local ctx = msg[2]
  return chacha20.crypt(ctx, key, nonce)
end

-- Sending
local message = "hello world"
local msg = encrypt(message)
print(textutils.serialiseJSON(msg))

-- Receiving
local receivedMsg = decrypt(msg)
print(receivedMsg)

-------------------------------------------

local function encrypt()
  local data  = "1"
  local key   = ByteArray.fromBytes("123456789abccdef")
  local nonce = chacha20.genNonce(12)

  return chacha20.crypt(data, key, nonce)
end



--local function decrypt

--print(encrypt())

--[[ rednet API
CHANNEL_BROADCAST = 65535
CHANNEL_REPEAT = 65533
MAX_ID_CHANNELS = 65500
broadcast(message, protocol: string)
close(modem: string)
host(protocol: string, hostname: string) ->
isOpen(modem: string) -> boolean
lookup(protocol: string, hostname: string) -> number, number
open(modem: string)
receive(protocol_filter: string, timeout: number)
run()
send(recipient: number, message, protocol: string) -> boolean
unhost(protocol: string)
]]
--[[
Rednet EMU
]]
local rednet = rednet

local rednet_emu = {
  CHANNEL_BROADCAST = rednet.CHANNEL_BROADCAST or 65535,
  CHANNEL_REPEAT    = rednet.CHANNEL_REPEAT or 65533,
  MAX_ID_CHANNELS   = rednet.MAX_ID_CHANNELS or 65500
}

function rednet_emu.broadcast(message, protocol)

end

function rednet_emu.close(modem)

end

function rednet_emu.host(protocol, hostname)

end

function rednet_emu.isOpen(modem)

end

function rednet_emu.lookup(protocol, hostname)

end

function rednet_emu.open(modem)

end

function rednet_emu.receive(protocol_filter, timeout)

end

function rednet_emu.run()

end

function rednet_emu.send(recipient, message, protocol)

end

function rednet_emu.unhost(protocol)

end
