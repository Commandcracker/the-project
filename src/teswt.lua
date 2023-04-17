local xmss = require("lib.xmss")
local ByteArray = require("lib.bytearray")

-- Generate a new XMSS key pair
local sk, pk = xmss.keygen(254, 6)

print("private key:")
print(sk)

--print(textutils.serialiseJSON(pk))

print(setmetatable(sk, ByteArray):toHex())
print(setmetatable(pk, ByteArray))

-- Sign a message
local message = "Hello, world!"
local signature = xmss.sign(sk, message)

-- Verify the signature
if xmss.verify(pk, signature, message) then
	print("Signature is valid!")
else
	print("Signature is invalid.")
end
