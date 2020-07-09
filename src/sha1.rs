// An implementation of RFC3174 (https://tools.ietf.org/rfc/rfc3174.txt)
// For practicality, only bit lengths that are multiples of 8 are allowed

trait Sha1able {
    // This function will return the last block appropriately padded
    fn sha1pad(&self) -> Vec<u8>;
}

impl Sha1able for &[u8] {
    fn sha1pad(&self) -> Vec<u8> {
        let block_len_bytes = 64;
        let mut res = vec![0u8; block_len_bytes];
        let byteslength = self.len();

        let end_of_last_whole_block = (byteslength / block_len_bytes) * block_len_bytes;
        let num_bytes_to_copy = byteslength - end_of_last_whole_block;
        res[num_bytes_to_copy] = 0x80;
        res[0..num_bytes_to_copy].copy_from_slice(&self[end_of_last_whole_block..byteslength]);

        let bitslength = byteslength * 8;
        res[block_len_bytes - 8..].copy_from_slice(&bitslength.to_ne_bytes());
        res
    }
}

impl Sha1able for Vec<u8> {
    fn sha1pad(&self) -> Vec<u8> {
        (&self[..]).sha1pad()
    }
}

fn K(t: usize) -> u32 {
    match t {
        0..=19 => return 0x5A827999,
        20..=39 => return 0x6ED9EBA1,
        40..=59 => return 0x8F1BBCDC,
        60..=79 => return 0xCA62C1D6,
        _ => panic!("sha1.rs: `t` out of range in `K` t={}", t)
    }
}

fn f(t: usize, b: u32, c: u32, d: u32) -> u32 {
    match t {
        0..=19 => return (b & c) | ((!b) & d),
        20..=39 | 60..=79 => return b ^ c ^ d,
        40..=59 => return (b & c) | (b & d) | (c & d),
        _ => panic!("sha1.rs: `t` out of range in `f` t={}", t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_padding() {
        // "abcde", right from the spec
        let input: Vec<u8> = vec![
            0b01100001,
            0b01100010,
            0b01100011,
            0b01100100,
            0b01100101
        ];

        // This is terrible, but rust doesn't seems to have a clean way
        // to turn Vec<i32> => Vec<u8> (or even &[u8]) without pulling
        // in a dependency or using unsafe code.
        let mut expected_usize = vec![
            0x61, 0x62, 0x63, 0x64, 0x65, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        expected_usize.extend_from_slice(&(0x28 as u64).to_ne_bytes());

        assert_eq!(
            &input.sha1pad(),
            &expected_usize
        )
    }
}
