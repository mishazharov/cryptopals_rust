// An implementation of RFC3174 (https://tools.ietf.org/rfc/rfc3174.txt)
// For practicality, only bit lengths that are multiples of 8 are allowed

trait Sha1Paddable {
    fn sha1pad(&self) -> Vec<u8>;
}

impl Sha1Paddable for Vec<u8> {
    fn sha1pad(&self) -> Vec<u8> {
        let mut res = self.to_vec();
        let byteslength = res.len();

        // Add 9 bytes for a u64, and byte. The byte=0b10000000 as defined in the spec
        // and appended to res. The other 8 bytes are for a u64 (length field, see spec)
        let num_non_zeros = byteslength + 9;

        // 64 bytes is 512 bits
        let num_new_zeros = 64 - (num_non_zeros) % 64;

        res.resize(num_new_zeros + num_non_zeros, 0);

        res[byteslength] = 0x80;

        // bitlength is the size of the original message in bits
        // Called `l` in the spec
        let bitlength = (byteslength * 8) as u64;

        let eight_from_end = res.len() - 8;
        res[eight_from_end..].copy_from_slice(&bitlength.to_ne_bytes());

        res
    }
}

impl Sha1Paddable for &[u8] {
    fn sha1pad(&self) -> Vec<u8> {
        let v = self.to_vec();
        v.sha1pad()
    }
}

impl Sha1Paddable for [u8] {
    fn sha1pad(&self) -> Vec<u8> {
        let v = self.to_vec();
        v.sha1pad()
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
