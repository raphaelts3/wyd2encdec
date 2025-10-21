import Foundation

func readKeys(path: String) -> Data? {
    guard let fileHandle = FileHandle(forReadingAtPath: path) else {
        print("Failed to open keys file")
        return nil
    }
    let data = fileHandle.readDataToEndOfFile()
    fileHandle.closeFile()
    return data
}

func readDataFile(path: String) -> Data? {
    guard let fileHandle = FileHandle(forReadingAtPath: path) else {
        print("Failed to open data file")
        return nil
    }
    let data = fileHandle.readDataToEndOfFile()
    fileHandle.closeFile()
    return data
}

func encrypt(decryptedFileRaw: inout Data, keys: Data) {
    var off = 0
    while off < decryptedFileRaw.count {
        let packetLength = Int(decryptedFileRaw.withUnsafeBytes { $0.load(fromByteOffset: off, as: UInt16.self) })
        var key = Int(decryptedFileRaw[off + 2])
        key = Int(keys[((key << 1) % 512)])
        for i in (off + 4)..<min(off + packetLength, decryptedFileRaw.count) {
            let mappedKey = Int(keys[((key % 256) << 1) % 512 + 1])
            var currValue = Int(decryptedFileRaw[i])
            switch i & 3 {
            case 0:
                currValue = (currValue + (mappedKey << 1)) & 255
            case 1:
                currValue = (currValue - (mappedKey >> 3)) & 255
            case 2:
                currValue = (currValue + (mappedKey << 2)) & 255
            case 3:
                currValue = (currValue - (mappedKey >> 5)) & 255
            default:
                break
            }
            decryptedFileRaw[i] = UInt8(currValue)
            key += 1
        }
        off += packetLength
    }
}

func decrypt(encryptedFileRaw: inout Data, keys: Data) {
    var off = 0
    while off < encryptedFileRaw.count {
        let packetLength = Int(encryptedFileRaw.withUnsafeBytes { $0.load(fromByteOffset: off, as: UInt16.self) })
        var key = Int(encryptedFileRaw[off + 2])
        key = Int(keys[(key << 1)])
        for i in (off + 4)..<min(off + packetLength, encryptedFileRaw.count) {
            let mappedKey = Int(keys[((key % 256) << 1) % 512 + 1])
            var currValue = Int(encryptedFileRaw[i])
            switch i & 3 {
            case 0:
                currValue = (currValue - (mappedKey << 1)) & 255
            case 1:
                currValue = (currValue + (mappedKey >> 3)) & 255
            case 2:
                currValue = (currValue - (mappedKey << 2)) & 255
            case 3:
                currValue = (currValue + (mappedKey >> 5)) & 255
            default:
                break
            }
            encryptedFileRaw[i] = UInt8(currValue)
            key += 1
        }
        off += packetLength
    }
}

@main
struct wyd2encdec {
    static func main() {
    let args = CommandLine.arguments
    guard args.count >= 5 else {
        exit(-1)
    }
    guard let keys = readKeys(path: args[1]) else {
        exit(-2)
    }
    guard var encryptedFileRaw = readDataFile(path: args[3]) else {
        exit(-3)
    }
    guard var decryptedFileRaw = readDataFile(path: args[4]) else {
        exit(-4)
    }
    let op = args[2]
    if op == "enc" {
        encrypt(decryptedFileRaw: &decryptedFileRaw, keys: keys)
        try? decryptedFileRaw.write(to: URL(fileURLWithPath: "./encoded.bin"))
    }
    if op == "dec" {
        decrypt(encryptedFileRaw: &encryptedFileRaw, keys: keys)
        try? encryptedFileRaw.write(to: URL(fileURLWithPath: "./decoded.bin"))
    }
    let diff = zip(encryptedFileRaw, decryptedFileRaw).filter { $0 != $1 }.count
    print("\(diff) differences")
}
}
