import os

fn read_keys(path string) ?[]u8 {
	data := os.read_file(path) or {
		eprintln('Failed to open keys file')
		return none
	}
	return data.bytes()
}

fn read_data_file(path string) ?([]u8, int) {
	data := os.read_file(path) or {
		eprintln('Failed to open data file')
		return none
	}
	return data.bytes(), data.len
}

fn encrypt(mut decrypted_file_raw []u8, length int, keys []u8) {
	mut off := 0
	for off < length {
		packet_length := (int(decrypted_file_raw[off + 1]) << 8) + int(decrypted_file_raw[off])
		mut key := int(decrypted_file_raw[off + 2])
		key = keys[(key << 1) % 512]
		for i := off + 4; i < off + packet_length; i++ {
			mapped_key := keys[((key % 256) << 1) % 512 + 1]
			mut curr_value := decrypted_file_raw[i]
			match i & 3 {
				0 { curr_value = u8((curr_value + (mapped_key << 1)) & 255) }
				1 { curr_value = u8((curr_value - (mapped_key >> 3)) & 255) }
				2 { curr_value = u8((curr_value + (mapped_key << 2)) & 255) }
				3 { curr_value = u8((curr_value - (mapped_key >> 5)) & 255) }
				else {}
			}
			decrypted_file_raw[i] = u8(curr_value)
			key++
		}
		off += packet_length
	}
}

fn decrypt(mut encrypted_file_raw []u8, length int, keys []u8) {
	mut off := 0
	for off < length {
		packet_length := (int(encrypted_file_raw[off + 1]) << 8) + int(encrypted_file_raw[off])
		mut key := int(encrypted_file_raw[off + 2])
		key = keys[key << 1]
		for i := off + 4; i < off + packet_length; i++ {
			mapped_key := keys[((key % 256) << 1) % 512 + 1]
			mut curr_value := encrypted_file_raw[i]
			match i & 3 {
				0 { curr_value = (curr_value - (mapped_key << 1)) & 255 }
				1 { curr_value = (curr_value + (mapped_key >> 3)) & 255 }
				2 { curr_value = (curr_value - (mapped_key << 2)) & 255 }
				3 { curr_value = (curr_value + (mapped_key >> 5)) & 255 }
				else {}
			}
			encrypted_file_raw[i] = curr_value
			key++
		}
		off += packet_length
	}
}

fn main() {
	if os.args.len < 5 {
		exit(1)
	}
	keys := read_keys(os.args[1]) or { exit(2) }

	mut encrypted_file_raw := []u8{}
    mut encrypted_file_raw_size := 0
	encrypted_file_raw, encrypted_file_raw_size = read_data_file(os.args[3]) or { exit(3) }

	mut decrypted_file_raw := []u8{}
    mut decrypted_file_raw_size := 0
	decrypted_file_raw, decrypted_file_raw_size = read_data_file(os.args[4]) or { exit(4) }

	op := os.args[2]
	if op == 'enc' {
		encrypt(mut decrypted_file_raw, decrypted_file_raw_size, keys)
		os.write_file_array('./encoded.bin', decrypted_file_raw) or { exit(5) }
	} else if op == 'dec' {
		decrypt(mut encrypted_file_raw, encrypted_file_raw_size, keys)
		os.write_file_array('./decoded.bin', encrypted_file_raw) or { exit(6) }
	}

	mut diff := 0
	for i in 0 .. encrypted_file_raw_size {
		if encrypted_file_raw[i] != decrypted_file_raw[i] {
			diff++
		}
	}
	println('$diff differences')
}
