import os

struct MsgHeader {
    size_      u16   // Packet size
    key_       u8    // Key used as seed for enc/dec
    hash_      u8    // Hash generated to validate the process
    code_      i16   // Internal packet identifier
    index_     i16   // Index from the user that sent the packet
    timestamp_ u32   // Timestamp usually get right before starting the enc/dec process
}

fn encrypt(keys []u8, mut decrypted_packets []&MsgHeader, decrypted_file_raw []u8) {
    for packet in decrypted_packets {
        mut ptr := unsafe { &u8(packet) }
        mut j := u16(4)
        mut key := keys[packet.key_ << 1]
        for j < packet.size_ {
            mapped_key := keys[((key % 256) << 1) + 1]
            unsafe {
                match j & 3 {
                    0 { ptr[j] += u8(mapped_key << 1) }
                    1 { ptr[j] -= u8(mapped_key >> 3) }
                    2 { ptr[j] += u8(mapped_key << 2) }
                    3 { ptr[j] -= u8(mapped_key >> 5) }
                    else {}
                }
            }
            j++
            key++
        }
    }
}

fn decrypt(keys []u8, mut encrypted_packets []&MsgHeader, encrypted_file_raw []u8) {
    for packet in encrypted_packets {
        mut ptr := unsafe { &u8(packet) }
        mut j := u16(4)
        mut key := keys[packet.key_ << 1]
        for j < packet.size_ {
            mapped_key := keys[((key % 256) << 1) + 1]
            unsafe {
                match j & 3 {
                    0 { ptr[j] -= u8(mapped_key << 1) }
                    1 { ptr[j] += u8(mapped_key >> 3) }
                    2 { ptr[j] -= u8(mapped_key << 2) }
                    3 { ptr[j] += u8(mapped_key >> 5) }
                    else {}
                }
            }
            j++
            key++
        }
    }
}

fn read_keys(file_path string) ?[]u8 {
    file := os.read_file(file_path) or {
        eprintln('Failed to open the keys file')
        return none
    }
    return file.bytes()
}

fn read_data_file(file_path string, mut packets []&MsgHeader) ?([]u8, int) {
    println('Reading data file ${file_path}')
    data := os.read_file(file_path) or {
        eprintln('Failed to open the data file')
        return none
    }
    file_size := data.len
    mut ptr := &u8(data.bytes().data)
    mut tmp_size := file_size
    mut result := []u8{len: file_size}
    for tmp_size > 0 {
        packet := unsafe { &MsgHeader(ptr) }
        packets << packet
        unsafe { ptr += packet.size_ }
        tmp_size -= packet.size_
    }
    return result, file_size
}

fn process_files(keys_file string, enc_file string, dec_file string, op string) {
    keys := read_keys(keys_file)
    if keys == none {
        return
    }

    mut encrypted_packets := []&MsgHeader{}
    mut decrypted_packets := []&MsgHeader{}

    mut size_encrypted_file := 0
    mut encrypted_file_raw := []u8{}
    mut decrypted_file_raw := []u8{}
    if op == "dec" {
        encrypted_file_raw, size_encrypted_file = read_data_file(enc_file, mut encrypted_packets) or { return }
    } else if op == "enc" {
        decrypted_file_raw, _ = read_data_file(dec_file, mut decrypted_packets) or { return }
    }

    if op == 'enc' {
        encrypt(keys, mut decrypted_packets, decrypted_file_raw)
        os.write_file('./encoded.bin', decrypted_file_raw.bytestr()) or {
            eprintln('Failed to write encoded file')
        }
    } else if op == 'dec' {
        decrypt(keys, mut encrypted_packets, encrypted_file_raw)
        os.write_file('./decoded.bin', encrypted_file_raw.bytestr()) or {
            eprintln('Failed to write decoded file')
        }
    }

    mut diff := 0
    for i in 0 .. size_encrypted_file {
        if encrypted_file_raw[i] != decrypted_file_raw[i] {
            diff++
        }
    }

    println('${diff} differences')
}

fn main() {
    if os.args.len < 5 {
        println('Not enough arguments')
        return
    }

    keys_file := os.args[1]
    op := os.args[2]
    enc_file := os.args[3]
    dec_file := os.args[4]

    process_files(keys_file, enc_file, dec_file, op)
}
