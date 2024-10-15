
function lshift (a, b)
    return ((a & 0xFFFFFFFF) << b) & 0xFFFFFFFF
end

function rshift (a, b)
    return ((a & 0xFFFFFFFF) >> b) & 0xFFFFFFFF
end
local keys = ""

function readKeys(path)
    local file = io.open(path, "rb")
    if not file then
        print("Failed to open keys file")
        return false, nil
    end
    local keys = file:read("*all")
    file:close()
    return true, keys
end

function readDataFile(path)
    local file = io.open(path, "rb")
    if not file then
        print("Failed to open data file")
        return false, nil, 0
    end
    local buffer = file:read("*all")
    local fileSize = #buffer
    file:close()
    return true, buffer, fileSize
end

function encrypt(decryptedFileRaw, length, keys)
    local off = 0
    while off < length do
        local packetLength = string.unpack("<I2", decryptedFileRaw, off + 1)
        local key = string.unpack("B", decryptedFileRaw, off + 3)
        key = string.unpack("B", keys, (lshift(key, 1) % 512) + 1)  -- Adjusted to use lshift
        for i = off + 4, off + packetLength - 1 do
            local mappedKey = string.unpack("B", keys, (lshift(key % 256, 1) % 512) + 2)  -- Adjusted
            local currValue = string.unpack("B", decryptedFileRaw, i + 1)
            -- print(key % 256, key, (lshift(key % 256, 1) % 512) + 1, mappedKey, currValue)
            if (i & 3) == 0 then
                -- print(currValue, mappedKey, lshift(mappedKey, 1), currValue + lshift(mappedKey, 1),(currValue + lshift(mappedKey, 1)) & 255)
                currValue = (currValue + lshift(mappedKey, 1)) & 255  -- Left shift
            elseif (i & 3) == 1 then
                currValue = (currValue - rshift(mappedKey, 3)) & 255  -- Right shift
            elseif (i & 3) == 2 then
                currValue = (currValue + lshift(mappedKey, 2)) & 255  -- Left shift
            elseif (i & 3) == 3 then
                currValue = (currValue - rshift(mappedKey, 5)) & 255  -- Right shift
            end
            decryptedFileRaw = decryptedFileRaw:sub(1, i) .. string.pack("B", currValue) .. decryptedFileRaw:sub(i + 2)
            key = key + 1
        end
        off = off + packetLength
    end
    return decryptedFileRaw
end

function decrypt(encryptedFileRaw, length, keys)
    local off = 0
    while off < length do
        local packetLength = string.unpack("<I2", encryptedFileRaw, off + 1)
        local key = string.unpack("B", encryptedFileRaw, off + 3)
        key = string.unpack("B", keys, (lshift(key, 1)) + 1)  -- Adjusted
        for i = off + 4, off + packetLength - 1 do
            local mappedKey = string.unpack("B", keys, (lshift(key % 256, 1) % 512) + 2)  -- Adjusted
            local currValue = string.unpack("B", encryptedFileRaw, i + 1)
            if (i & 3) == 0 then
                currValue = (currValue - lshift(mappedKey, 1)) & 255  -- Left shift
            elseif (i & 3) == 1 then
                currValue = (currValue + rshift(mappedKey, 3)) & 255  -- Right shift
            elseif (i & 3) == 2 then
                currValue = (currValue - lshift(mappedKey, 2)) & 255  -- Left shift
            elseif (i & 3) == 3 then
                currValue = (currValue + rshift(mappedKey, 5)) & 255  -- Right shift
            end
            encryptedFileRaw = encryptedFileRaw:sub(1, i) .. string.pack("B", currValue) .. encryptedFileRaw:sub(i + 2)
            key = key + 1
        end
        off = off + packetLength
    end
    return encryptedFileRaw
end

if #arg < 4 then
    os.exit(-1)
end

local keysLoaded, keys = readKeys(arg[1])
if not keysLoaded then
    os.exit(-2)
end

local encryptedFileLoaded, encryptedFileRaw, encryptedFileRawSize = readDataFile(arg[3])
if not encryptedFileLoaded then
    os.exit(-3)
end

local decryptedFileLoaded, decryptedFileRaw, decryptedFileRawSize = readDataFile(arg[4])
if not decryptedFileLoaded then
    os.exit(-4)
end

local op = arg[2]
if op == "enc" then
    decryptedFileRaw = encrypt(decryptedFileRaw, decryptedFileRawSize, keys)
    local out = io.open("./encoded.bin", "wb")
    out:write(decryptedFileRaw)
    out:close()
elseif op == "dec" then
    encryptedFileRaw = decrypt(encryptedFileRaw, encryptedFileRawSize, keys)
    local out = io.open("./decoded.bin", "wb")
    out:write(encryptedFileRaw)
    out:close()
end

local diff = 0
for i = 1, encryptedFileRawSize do
    if encryptedFileRaw:sub(i, i) ~= decryptedFileRaw:sub(i, i) then
        diff = diff + 1
    end
end

print(diff .. " differences")
