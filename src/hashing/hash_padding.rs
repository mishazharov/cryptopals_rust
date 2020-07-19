pub const HASH_BLOCK_LEN_BYTES: usize = 64;

pub trait HashPaddable {
    fn hashpad(&self, big_endian: bool) -> Vec<u8>;
}

impl HashPaddable for Vec<u8> {
    // big_endian specifies if the length is encoded in big or little endian
    fn hashpad(&self, big_endian: bool) -> Vec<u8> {
        let mut res = self.to_vec();
        let byteslength = res.len();

        // Add 9 bytes for a u64, and byte. The byte=0b10000000 as defined in the spec
        // and appended to res. The other 8 bytes are for a u64 (length field, see spec)
        let num_non_zeros = byteslength + 9;

        // 64 bytes is 512 bits
        let mut num_new_zeros = HASH_BLOCK_LEN_BYTES - (num_non_zeros) % HASH_BLOCK_LEN_BYTES;
        if num_new_zeros == HASH_BLOCK_LEN_BYTES {
            num_new_zeros = 0;
        }

        res.resize(num_new_zeros + num_non_zeros, 0);

        res[byteslength] = 0x80;

        // bitlength is the size of the original message in bits
        // Called `l` in the spec
        let bitlength = (byteslength * 8) as u64;

        let eight_from_end = res.len() - 8;
        res[eight_from_end..].copy_from_slice(
            &if big_endian {
                bitlength.to_be_bytes()
            } else {
                bitlength.to_le_bytes()
            }
        );

        res
    }
}

impl HashPaddable for &[u8] {
    fn hashpad(&self, big_endian: bool) -> Vec<u8> {
        self.to_vec().hashpad(big_endian)
    }
}

impl HashPaddable for &Vec::<u8> {
    fn hashpad(&self, big_endian: bool) -> Vec<u8> {
        self.to_vec().hashpad(big_endian)
    }
}


pub fn s(n: usize, x: u32) -> u32 {
    (x << n) | (x >> (32 - n))
}
