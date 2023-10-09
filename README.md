# WYD2EncDec
This project consists in implemeting WYD2 Enc/Dec main loop using multiple programming languages.

## Data
The project has a basic keys.dat and a set of packets locate inside [data](/data) folder.

### Files 
Since the programs only have to ENC/DEC a single packet, there are provided in this repository samples from the _Lock Password_ packets that includes:

 - Try a password (Client -> Server): _0xFDE_
 - Wrong password (Server -> Client): _0xFDF_
 - Correct password (Server -> Client): _0xFDE_

The files provided are:
 - [packets.cap](/data/packets/lock-password/packets.cap) is a Packet Capture file with the whole TCP packets, you can use (WireShark)[https://www.wireshark.org/]
 - [packets-encrypted.bin](/data/packets/lock-password/packets-encrypted.bin) contains only the raw data from each packet present on _packets.cap_
 - [packets-decrypted.bin](/data/packets/lock-password/packets-decrypted.bin) also contains only the data from each packet, but already decrypted
 - [packets-dumped.txt](/data/packets/lock-password/packets-dumped.txt) has the _readable_
 version of each packet present at _packets-decrypted.bin_

 ### Packet Structure
 A WYD2 has the following structure as its basic data packet, it already give a lot of insights and one of them is that it always have at least **12 bytes**.

 ```cpp
struct MsgHeader {
  uint16_t size_; //Packet size
  uint8_t key_; //Key used as seed for enc/dec
  uint8_t hash_; //Hash generated to validate the process
  int16_t code_; //Internal packet identifier
  int16_t index_; //Index from the user that sent the packet
  uint32_t timestamp_; //Timestamp usually get right before starting the enc/dec process
  ...
};
```

## Implementations
See the checklist below to see what implementations are ready,
it also has link to the language specific documentation.

- [x] [C++](/cpp)
- [x] [C#](/csharp)
- [x] [Java](/java)
- [x] [Go](/go)
- [x] [JS](/js)
- [x] [PHP](/php)
- [x] [Rust](/rust)

### Executing
All implementations should be executed providing three arguments:
 1. The _**path**_ for the _**keys** file
 2. **enc|dec**
 3. The _**path**_ for the _**encrypted bin**_ file
 4. The _**path**_ for the _**decrypted bin**_ file

## Authors
 - Raphael Tomé Santana

## License
This project is licensed under the MIT License - see the LICENSE.md file for details
