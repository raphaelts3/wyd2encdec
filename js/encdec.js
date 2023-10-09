"use strict";

const fs = require("fs");

class EncDec {
  constructor(keysPath, encryptedPath, decryptedPath) {
    this._keysPath = keysPath;
    this._encryptedPath = encryptedPath;
    this._decryptedPath = decryptedPath;
    this._keys = null;
  }

  _encrypt(decryptedPackets) {
    for (const packet of decryptedPackets) {
      const view = new DataView(packet.buffer);
      const packetKey = view.getUint8(2);
      const packetSize = view.getUint16(0, true);
      let j = 4;
      let key = this._keys[packetKey << 1];
      do {
        const mappedKey = this._keys[(key % 256 << 1) + 1];
        switch (j & 3) {
          case 0:
            packet[j] = packet[j] + (mappedKey << 1);
            break;
          case 1:
            packet[j] = packet[j] - (mappedKey >> 3);
            break;
          case 2:
            packet[j] = packet[j] + (mappedKey << 2);
            break;
          case 3:
            packet[j] = packet[j] - (mappedKey >> 5);
            break;
        }
        j++;
        key++;
      } while (j < packetSize);
    }
  }

  _decrypt(encryptedPackets) {
    for (const packet of encryptedPackets) {
      const view = new DataView(packet.buffer);
      const packetKey = view.getUint8(2);
      const packetSize = view.getUint16(0, true);
      let j = 4;
      let key = this._keys[packetKey << 1];
      do {
        const mappedKey = this._keys[(key % 256 << 1) + 1];
        switch (j & 3) {
          case 0:
            packet[j] = packet[j] - (mappedKey << 1);
            break;
          case 1:
            packet[j] = packet[j] + (mappedKey >> 3);
            break;
          case 2:
            packet[j] = packet[j] - (mappedKey << 2);
            break;
          case 3:
            packet[j] = packet[j] + (mappedKey >> 5);
            break;
        }
        j++;
        key++;
      } while (j < packetSize);
    }
  }

  _readKeys() {
    if (!this._keys) {
      const buffer = fs.readFileSync(this._keysPath, { flags: "rb" });
      this._keys = Uint8Array.from(buffer);
    }
  }

  _readDataFile(filePath, packets) {
    const buffer = fs.readFileSync(filePath, { flags: "rb" });
    const fileSize = buffer.byteLength;
    const dataRaw = new Uint8Array(buffer);

    const view = new DataView(dataRaw.buffer, 0);
    let offset = 0;
    while (offset < fileSize) {
      const packetSize = view.getUint16(offset, true);
      packets.push(
        Uint8Array.from(
          Buffer.from(dataRaw.buffer.slice(offset, offset + packetSize))
        )
      );
      offset += packetSize;
    }
  }

  _writeDataFile(filePath, packets) {
    const file = fs.openSync(filePath, "w");
    for (let packet of packets) {
      fs.writeSync(file, Buffer.from(packet), 0, packet.byteLength);
    }
    fs.closeSync(file);
  }

  encrypt() {
    this._readKeys(this.keysPath);
    let decryptedPackets = [];
    this._readDataFile(this._decryptedPath, decryptedPackets);
    this._encrypt(decryptedPackets);
    this._writeDataFile("./encoded.bin", decryptedPackets);
  }

  decrypt() {
    this._readKeys(this.keysPath);
    let encryptedPackets = [];
    this._readDataFile(this._encryptedPath, encryptedPackets);
    this._decrypt(encryptedPackets);
    this._writeDataFile("./decoded.bin", encryptedPackets);
  }
}

module.exports = EncDec;
