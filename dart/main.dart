import 'dart:io';
import 'dart:typed_data';

Uint8List keys = Uint8List.fromList(List.filled(512, 0));
late int sizeEncryptedFile;
late List<int> encryptedFileRaw;
List<Uint8List> encryptedPackets = [];
late int sizeDecryptedFile;
late List<int> decryptedFileRaw;
List<Uint8List> decryptedPackets = [];

void encrypt() {
  for (var packet in decryptedPackets) {
    var bytes = packet.buffer.asByteData();
    var j = 4;
    var key = keys[bytes.getUint8(2) << 1] & 0xFF;
    var packetSize = bytes.getUint16(0, Endian.little);
    for (; j < packetSize; j++) {
      var mappedKey = keys[((key % 256) << 1) + 1] & 0xFFFFFFFF;
      switch (j & 3) {
        case 0:
          packet[j] = (packet[j] + (mappedKey << 1)) & 0xFF;
          break;
        case 1:
          packet[j] = (packet[j] - (mappedKey >> 3)) & 0xFF;
          break;
        case 2:
          packet[j] = (packet[j] + (mappedKey << 2)) & 0xFF;
          break;
        case 3:
          packet[j] = (packet[j] - (mappedKey >> 5)) & 0xFF;
          break;
      }
      key++;
    }
  }
}

void decrypt() {
  for (var packet in encryptedPackets) {
    var bytes = packet.buffer.asByteData();
    var j = 4;
    var key = keys[bytes.getUint8(2) << 1] & 0xFF;
    var packetSize = bytes.getUint16(0, Endian.little);
    for (; j < packetSize; j++) {
      var mappedKey = keys[((key % 256) << 1) + 1] & 0xFFFFFFFF;
      switch (j & 3) {
        case 0:
          packet[j] = (packet[j] - (mappedKey << 1)) & 0xFF;
          break;
        case 1:
          packet[j] = (packet[j] + (mappedKey >> 3)) & 0xFF;
          break;
        case 2:
          packet[j] = (packet[j] - (mappedKey << 2)) & 0xFF;
          break;
        case 3:
          packet[j] = (packet[j] + (mappedKey >> 5)) & 0xFF;
          break;
      }
      key++;
    }
  }
}

bool readKeys(String filePath) {
  var file = File(filePath);
  try {
    var keysFile = file.readAsBytesSync();
    if (keysFile.length < 512) {
      print('Failed to read the keys file');
      return false;
    }
    keys = keysFile;
    return true;
  } catch (e) {
    print('Failed to open the keys file');
    print(e);
    return false;
  }
}

int readDataFile(String filePath, List<Uint8List> packets) {
  var file = File(filePath);
  try {
    var dataFile = file.readAsBytesSync();
    var bytes = dataFile.buffer.asByteData();
    var fileSize = dataFile.length;
    var i = 0;
    while (i < fileSize) {
      var packetSize = bytes.getUint16(i, Endian.little);
      packets.add(Uint8List.fromList(dataFile.sublist(i, i + packetSize)));
      i += packetSize;
    }
    return fileSize;
  } catch (e) {
    print('Failed to open the data file: $filePath');
    print(e);
    return 0;
  }
}

void main(List<String> args) {
  if (args.length < 5) {
    print('Not enough arguments');
    exit(-1);
  }
  if (!readKeys(args[1])) {
    exit(-2);
  }
  sizeEncryptedFile = readDataFile(args[3], encryptedPackets);
  if (sizeEncryptedFile == 0) {
    exit(-3);
  }
  sizeDecryptedFile = readDataFile(args[4], decryptedPackets);
  if (sizeDecryptedFile == 0) {
    exit(-4);
  }
  var op = args[2];
  if (op == 'enc') {
    encrypt();
    var out = File('./encoded.bin');
    var sink = out.openSync(mode: FileMode.write);
    for (var packet in decryptedPackets) {
      sink.writeFromSync(packet);
    }
    sink.closeSync();
  } else if (op == 'dec') {
    decrypt();
    var out = File('./decoded.bin');
    var sink = out.openSync(mode: FileMode.write);
    for (var packet in encryptedPackets) {
      sink.writeFromSync(packet);
    }
    sink.closeSync();
  }
  var diff = 0;
  for (var j = 0; j < encryptedPackets.length; j++) {
    for (var i = 0; i < encryptedPackets[j].length; i++) {
      if (encryptedPackets[j][i] != decryptedPackets[j][i]) {
        diff++;
      }
    }
  }
  print('$diff differences');
}
