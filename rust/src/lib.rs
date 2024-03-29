pub mod encdec {
    #![allow(arithmetic_overflow)]
    use bytes::Buf;
    use std::fs::File;
    use std::io::Cursor;
    use std::io::Read;
    use std::mem;
    use std::path::Path;
    use std::ptr;
    use std::str;
    pub trait Packet {
        fn get_header(&self) -> &MsgHeader;
    }

    //MsgHeader defines the basic struct for a WYD2 packet header
    #[repr(C)]
    pub struct MsgHeader {
        size: u16,      //Packet size
        key: u8,        //Key used as seed for enc/dec
        hash: u8,       //Hash generated to validate the process
        code: i16,      //Internal packet identifier
        index: i16,     //Index from the user that sent the packet
        timestamp: u32, //Timestamp usually get right before starting the enc/dec process
    }

    //MsgLockPasswordRequest defines the struct for a WYD2 LockPasswordRequest
    #[repr(C)]
    pub struct MsgLockPasswordRequest {
        header: MsgHeader,  //Header
        password: [u8; 16], //ASCII Password
        change: i32,        // Flag to indicate if request a password change
    }

    impl Packet for MsgHeader {
        fn get_header(&self) -> &MsgHeader {
            return self;
        }
    }

    impl Packet for MsgLockPasswordRequest {
        fn get_header(&self) -> &MsgHeader {
            return &self.header;
        }
    }

    pub fn read_keys(file_path: &String, keys: &mut [u8]) -> () {
        // Create a path to the desired file
        let path = Path::new(&file_path);
        let mut file = match File::open(&path) {
            Err(why) => panic!("Failed to open the keys file: {}", why),
            Ok(file) => file,
        };
        // read up to 512 bytes
        let n = match file.read(keys) {
            Err(why) => panic!("Failed to read the keys file: {}", why),
            Ok(n) => n,
        };
        if n != 512 {
            panic!("Failed to read the keys file")
        }
    }

    pub fn read_raw_file(file_path: &String) -> Vec<u8> {
        // Create a path to the desired file
        let path = Path::new(&file_path);
        let mut file = match File::open(&path) {
            Err(why) => panic!("Failed to open the keys file: {}", why),
            Ok(file) => file,
        };
        let mut vec_data = Vec::new();
        match file.read_to_end(&mut vec_data) {
            Err(why) => panic!("Failed to read the keys file: {}", why),
            Ok(n) => n,
        };
        vec_data
    }

    pub fn encrypt(raw_data: &mut Vec<u8>, keys: &[u8]) -> Vec<u8> {
        let mut index: isize = 0;
        let end_index: isize = raw_data.len() as isize;

        while index != end_index {
            let packet_size =
                ((raw_data[index as usize + 1] as isize) << 8) + raw_data[index as usize] as isize;
            let mut key = keys[(raw_data[index as usize + 2] as usize) << 1] as usize;
            let mut j = 4;
            while j < packet_size {
                let mapped_key = keys[((key % 256) << 1) + 1] as u32;
                let current_index = (index + j) as usize;
                let mut off: u8 = raw_data[current_index];
                match j & 3 {
                    0 => off = off.wrapping_add((mapped_key << 1) as u8),
                    1 => off = off.wrapping_sub((mapped_key >> 3) as u8),
                    2 => off = off.wrapping_add((mapped_key << 2) as u8),
                    _ => off = off.wrapping_sub((mapped_key >> 5) as u8),
                }
                raw_data[current_index] = off;
                j += 1;
                key += 1;
            }
            index += packet_size;
        }
        raw_data.to_vec()
    }

    pub fn decrypt(raw_data: &mut Vec<u8>, keys: &[u8]) -> Vec<u8> {
        let mut index: isize = 0;
        let end_index: isize = raw_data.len() as isize;
        let ptr: *const u8 = raw_data.as_ptr();
        let min_size = mem::size_of::<MsgHeader>() as isize;

        while (end_index - index) >= min_size {
            // SAFETY: header is always at least size_of<MsgHeader> sized
            unsafe {
                let current_ptr = ptr.offset(index as isize) as *mut u8;
                let header = current_ptr as *const MsgHeader;
                let packet_size = (*header).size as isize;
                // SAFETY: packet_size is always less or equal to number of remaining bytes
                if (end_index - index) >= packet_size {
                    let mut j = 4;
                    let mut key = keys[((*header).key as usize) << 1] as usize;
                    while j < packet_size {
                        let mapped_key = keys[((key % 256) << 1) + 1] as u32;
                        let off = current_ptr.offset(j as isize) as *mut u8;
                        match j & 3 {
                            0 => *off = (*off).wrapping_sub((mapped_key << 1) as u8),
                            1 => *off = (*off).wrapping_add((mapped_key as i32 >> 3) as u8),
                            2 => *off = (*off).wrapping_sub((mapped_key << 2) as u8),
                            _ => *off = (*off).wrapping_add((mapped_key as i32 >> 5) as u8),
                        }
                        j += 1;
                        key += 1;
                    }
                    index += packet_size;
                } else {
                    index += end_index - index;
                }
            }
        }
        raw_data.to_vec()
    }

    pub fn decrypt_non_null(raw_data: &mut Vec<u8>, keys: &[u8]) -> Vec<u8> {
        let mut index: isize = 0;
        let end_index: isize = raw_data.len() as isize;
        let ptr: *const u8 = raw_data.as_ptr();
        let min_size = mem::size_of::<MsgHeader>() as isize;

        while (end_index - index) >= min_size {
            // SAFETY: header is always at least size_of<MsgHeader> sized
            let current_ptr = unsafe { ptr.offset(index as isize) as *mut u8 };
            let header = ptr::NonNull::<MsgHeader>::new(current_ptr as *mut MsgHeader)
                .expect("Ptr should not be null!");
            let ref_header = unsafe { header.as_ref() };
            let packet_size = ref_header.size as isize;
            // SAFETY: packet_size is always less or equal to number of remaining bytes
            if (end_index - index) >= packet_size {
                let mut j = 4;
                let mut key = keys[(ref_header.key as usize) << 1] as usize;
                while j < packet_size {
                    let mapped_key = keys[((key % 256) << 1) + 1] as u32;
                    // SAFETY: packet_size is always less or equal to number of remaining bytes
                    unsafe {
                        let off = current_ptr.offset(j as isize) as *mut u8;
                        match j & 3 {
                            0 => *off = (*off).wrapping_sub((mapped_key << 1) as u8),
                            1 => *off = (*off).wrapping_add((mapped_key as i32 >> 3) as u8),
                            2 => *off = (*off).wrapping_sub((mapped_key << 2) as u8),
                            _ => *off = (*off).wrapping_add((mapped_key as i32 >> 5) as u8),
                        }
                    }
                    j += 1;
                    key += 1;
                }
                index += packet_size;
            } else {
                index += end_index - index;
            }
        }
        raw_data.to_vec()
    }

    pub fn decrypt_cursor(raw_data: &mut Vec<u8>, keys: &[u8]) -> Vec<u8> {
        let mut buffer = Cursor::new(raw_data);
        let mut index = 0 as usize;
        let end_index = buffer.get_ref().len();
        let min_size = mem::size_of::<MsgHeader>();

        while (end_index - index) >= min_size {
            let packet_size = buffer.get_u16_le() as usize;
            if (end_index - index) >= packet_size {
                let dst = &mut buffer.get_mut()[index..index + packet_size];
                // src.get_ref()[2] = MsgHeader.key
                let mut key = keys[(dst[2] as usize) << 1] as usize;
                for i in 4..packet_size {
                    let mapped_key = keys[((key % 256) << 1) + 1] as u32;
                    match i & 3 {
                        0 => dst[i] = (dst[i]).wrapping_sub((mapped_key << 1) as u8),
                        1 => dst[i] = (dst[i]).wrapping_add((mapped_key as i32 >> 3) as u8),
                        2 => dst[i] = (dst[i]).wrapping_sub((mapped_key << 2) as u8),
                        _ => dst[i] = (dst[i]).wrapping_add((mapped_key as i32 >> 5) as u8),
                    }
                    key += 1;
                }
                index += packet_size;
            } else {
                index += end_index - index;
            }
            buffer.set_position(index as u64);
        }
        buffer.get_ref().to_vec()
    }

    pub unsafe fn unsafe_handle_msg_lock_password_request(
        msg_lock_password_request: *const MsgLockPasswordRequest,
    ) -> () {
        print!(
            "{}#unsafe",
            str::from_utf8(&((*msg_lock_password_request).password)).unwrap()
        );
    }

    pub fn handle_msg_lock_password_request(
        msg_lock_password_request: &MsgLockPasswordRequest,
    ) -> () {
        print!(
            "{}#safe",
            str::from_utf8(&((*msg_lock_password_request).password)).unwrap()
        );
    }

    pub fn handle_packets(raw_data: &Vec<u8>) -> () {
        if raw_data.len() < 12 {
            // Not a valid packet
            return;
        }
        print!("init v1 handler");
        let src_ptr: *const u8 = raw_data.as_ptr();
        let header = src_ptr as *const MsgHeader;
        // SAFETY: header is not null and len(header) is > 12 which means `.code` is valid
        let code = unsafe { (*header).code };
        if code == 0xFDE {
            unsafe {
                unsafe_handle_msg_lock_password_request(src_ptr as *const MsgLockPasswordRequest);
            }
            let mut packet = mem::MaybeUninit::<MsgLockPasswordRequest>::uninit();
            let dst_ptr = packet.as_mut_ptr();
            unsafe {
                ptr::copy_nonoverlapping(
                    src_ptr,
                    dst_ptr as *mut u8,
                    mem::size_of::<MsgLockPasswordRequest>(),
                );
            }
            handle_msg_lock_password_request(unsafe { &packet.assume_init_mut() });
        }
        print!("finish v1 handler");
        print!("init v2 handler");
        let header_v2 = ptr::NonNull::<MsgHeader>::new(raw_data.as_ptr() as *mut MsgHeader)
            .expect("Ptr should not be null!");
        let ref_header = unsafe { header_v2.as_ref() };
        let code = ref_header.code;
        if code == 0xFDE {
            handle_msg_lock_password_request(unsafe {
                header_v2.cast::<MsgLockPasswordRequest>().as_ref()
            });
        }
        print!("finish v2 handler");
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        fn default_keys() -> Vec<u8> {
            vec![
                0x84, 0x87, 0x37, 0xD7, 0xEA, 0x79, 0x91, 0x7D, 0x4B, 0x4B, 0x85, 0x7D, 0x87, 0x81,
                0x91, 0x7C, 0x0F, 0x73, 0x91, 0x91, 0x87, 0x7D, 0x0D, 0x7D, 0x86, 0x8F, 0x73, 0x0F,
                0xE1, 0xDD, 0x85, 0x7D, 0x05, 0x7D, 0x85, 0x83, 0x87, 0x9C, 0x85, 0x33, 0x0D, 0xE2,
                0x87, 0x19, 0x0F, 0x79, 0x85, 0x86, 0x37, 0x7D, 0xD7, 0xDD, 0xE9, 0x7D, 0xD7, 0x7D,
                0x85, 0x79, 0x05, 0x7D, 0x0F, 0xE1, 0x87, 0x7E, 0x23, 0x87, 0xF5, 0x79, 0x5F, 0xE3,
                0x4B, 0x83, 0xA3, 0xA2, 0xAE, 0x0E, 0x14, 0x7D, 0xDE, 0x7E, 0x85, 0x7A, 0x85, 0xAF,
                0xCD, 0x7D, 0x87, 0xA5, 0x87, 0x7D, 0xE1, 0x7D, 0x88, 0x7D, 0x15, 0x91, 0x23, 0x7D,
                0x87, 0x7C, 0x0D, 0x7A, 0x85, 0x87, 0x17, 0x7C, 0x85, 0x7D, 0xAC, 0x80, 0xBB, 0x79,
                0x84, 0x9B, 0x5B, 0xA5, 0xD7, 0x8F, 0x05, 0x0F, 0x85, 0x7E, 0x85, 0x80, 0x85, 0x98,
                0xF5, 0x9D, 0xA3, 0x1A, 0x0D, 0x19, 0x87, 0x7C, 0x85, 0x7D, 0x84, 0x7D, 0x85, 0x7E,
                0xE7, 0x97, 0x0D, 0x0F, 0x85, 0x7B, 0xEA, 0x7D, 0xAD, 0x80, 0xAD, 0x7D, 0xB7, 0xAF,
                0x0D, 0x7D, 0xE9, 0x3D, 0x85, 0x7D, 0x87, 0xB7, 0x23, 0x7D, 0xE7, 0xB7, 0xA3, 0x0C,
                0x87, 0x7E, 0x85, 0xA5, 0x7D, 0x76, 0x35, 0xB9, 0x0D, 0x6F, 0x23, 0x7D, 0x87, 0x9B,
                0x85, 0x0C, 0xE1, 0xA1, 0x0D, 0x7F, 0x87, 0x7D, 0x84, 0x7A, 0x84, 0x7B, 0xE1, 0x86,
                0xE8, 0x6F, 0xD1, 0x79, 0x85, 0x19, 0x53, 0x95, 0xC3, 0x47, 0x19, 0x7D, 0xE7, 0x0C,
                0x37, 0x7C, 0x23, 0x7D, 0x85, 0x7D, 0x4B, 0x79, 0x21, 0xA5, 0x87, 0x7D, 0x19, 0x7D,
                0x0D, 0x7D, 0x15, 0x91, 0x23, 0x7D, 0x87, 0x7C, 0x85, 0x7A, 0x85, 0xAF, 0xCD, 0x7D,
                0x87, 0x7D, 0xE9, 0x3D, 0x85, 0x7D, 0x15, 0x79, 0x85, 0x7D, 0xC1, 0x7B, 0xEA, 0x7D,
                0xB7, 0x7D, 0x85, 0x7D, 0x85, 0x7D, 0x0D, 0x7D, 0xE9, 0x73, 0x85, 0x79, 0x05, 0x7D,
                0xD7, 0x7D, 0x85, 0xE1, 0xB9, 0xE1, 0x0F, 0x65, 0x85, 0x86, 0x2D, 0x7D, 0xD7, 0xDD,
                0xA3, 0x8E, 0xE6, 0x7D, 0xDE, 0x7E, 0xAE, 0x0E, 0x0F, 0xE1, 0x89, 0x7E, 0x23, 0x7D,
                0xF5, 0x79, 0x23, 0xE1, 0x4B, 0x83, 0x0C, 0x0F, 0x85, 0x7B, 0x85, 0x7E, 0x8F, 0x80,
                0x85, 0x98, 0xF5, 0x7A, 0x85, 0x1A, 0x0D, 0xE1, 0x0F, 0x7C, 0x89, 0x0C, 0x85, 0x0B,
                0x23, 0x69, 0x87, 0x7B, 0x23, 0x0C, 0x1F, 0xB7, 0x21, 0x7A, 0x88, 0x7E, 0x8F, 0xA5,
                0x7D, 0x80, 0xB7, 0xB9, 0x18, 0xBF, 0x4B, 0x19, 0x85, 0xA5, 0x91, 0x80, 0x87, 0x81,
                0x87, 0x7C, 0x0F, 0x73, 0x91, 0x91, 0x84, 0x87, 0x37, 0xD7, 0x86, 0x79, 0xE1, 0xDD,
                0x85, 0x7A, 0x73, 0x9B, 0x05, 0x7D, 0x0D, 0x83, 0x87, 0x9C, 0x85, 0x33, 0x87, 0x7D,
                0x85, 0x0F, 0x87, 0x7D, 0x0D, 0x7D, 0xF6, 0x7E, 0x87, 0x7D, 0x88, 0x19, 0x89, 0xF5,
                0xD1, 0xDD, 0x85, 0x7D, 0x8B, 0xC3, 0xEA, 0x7A, 0xD7, 0xB0, 0x0D, 0x7D, 0x87, 0xA5,
                0x87, 0x7C, 0x73, 0x7E, 0x7D, 0x86, 0x87, 0x23, 0x85, 0x10, 0xD7, 0xDF, 0xED, 0xA5,
                0xE1, 0x7A, 0x85, 0x23, 0xEA, 0x7E, 0x85, 0x98, 0xAD, 0x79, 0x86, 0x7D, 0x85, 0x7D,
                0xD7, 0x7D, 0xE1, 0x7A, 0xF5, 0x7D, 0x85, 0xB0, 0x2B, 0x37, 0xE1, 0x7A, 0x87, 0x79,
                0x84, 0x7D, 0x73, 0x73, 0x87, 0x7D, 0x23, 0x7D, 0xE9, 0x7D, 0x85, 0x7E, 0x02, 0x7D,
                0xDD, 0x2D, 0x87, 0x79, 0xE7, 0x79, 0xAD, 0x7C, 0x23, 0xDA, 0x87, 0x0D, 0x0D, 0x7B,
                0xE7, 0x79, 0x9B, 0x7D, 0xD7, 0x8F, 0x05, 0x7D, 0x0D, 0x34, 0x8F, 0x7D, 0xAD, 0x87,
                0xE9, 0x7C, 0x85, 0x80, 0x85, 0x79, 0x8A, 0xC3, 0xE7, 0xA5, 0xE8, 0x6B, 0x0D, 0x74,
                0x10, 0x73, 0x33, 0x17, 0x0D, 0x37, 0x21, 0x19,
            ]
        }

        fn default_decrypted() -> Vec<u8> {
            vec![
                0x20, 0x00, 0xBB, 0x58, 0xDE, 0x0F, 0x00, 0x00, 0xC1, 0x78, 0xB9, 0x95, 0x30, 0x32,
                0x34, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x11, 0xCC, 0xDF, 0x0F, 0x00, 0x00, 0xC1, 0x78,
                0xB9, 0x95,
            ]
        }

        fn default_encrypted() -> Vec<u8> {
            vec![
                0x20, 0x00, 0xBB, 0x58, 0xD8, 0xF3, 0x84, 0xFD, 0xCD, 0x69, 0x2D, 0x91, 0x2A, 0x23,
                0x6C, 0x32, 0xFC, 0xF1, 0xE4, 0xF9, 0x06, 0xFF, 0xEC, 0xFD, 0x00, 0xED, 0xE8, 0x00,
                0xC2, 0xF1, 0x30, 0x00, 0x0C, 0x00, 0x11, 0xCC, 0xD9, 0xF3, 0x84, 0xFD, 0xCD, 0x69,
                0x2D, 0x91,
            ]
        }

        #[test]
        fn test_encrypt() {
            let keys = default_keys();
            let encrypted = default_encrypted();
            let mut decrypted = default_decrypted();
            assert_eq!(encrypt(&mut decrypted, &keys), encrypted);
        }

        #[test]
        fn test_decrypt() {
            let keys = default_keys();
            let mut encrypted = default_encrypted();
            let decrypted = default_decrypted();
            assert_eq!(decrypt(&mut encrypted, &keys), decrypted);
        }

        #[test]
        fn test_decrypt_non_null() {
            let keys = default_keys();
            let mut encrypted = default_encrypted();
            let decrypted = default_decrypted();
            assert_eq!(decrypt_non_null(&mut encrypted, &keys), decrypted);
        }

        #[test]
        fn test_decrypt_cursor() {
            let keys = default_keys();
            let mut encrypted = default_encrypted();
            let decrypted = default_decrypted();
            assert_eq!(decrypt_cursor(&mut encrypted, &keys), decrypted);
        }
    }
}
