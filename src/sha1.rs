// An implementation of RFC3174 (https://tools.ietf.org/rfc/rfc3174.txt)
// For practicality, only bit lengths that are multiples of 8 are allowed
use std::convert::TryInto;
use std::num::Wrapping;

const BLOCK_LEN_BYTES: usize = 64;
const SHA1_LEN_BYTES: usize = 20;

pub trait Sha1able {
    fn sha1pad(&self) -> Vec<u8>;
}

impl Sha1able for Vec<u8> {
    fn sha1pad(&self) -> Vec<u8> {
        let mut res = self.to_vec();
        let byteslength = res.len();

        // Add 9 bytes for a u64, and byte. The byte=0b10000000 as defined in the spec
        // and appended to res. The other 8 bytes are for a u64 (length field, see spec)
        let num_non_zeros = byteslength + 9;

        // 64 bytes is 512 bits
        let num_new_zeros = BLOCK_LEN_BYTES - (num_non_zeros) % BLOCK_LEN_BYTES;

        res.resize(num_new_zeros + num_non_zeros, 0);

        res[byteslength] = 0x80;

        // bitlength is the size of the original message in bits
        // Called `l` in the spec
        let bitlength = (byteslength * 8) as u64;

        let eight_from_end = res.len() - 8;
        res[eight_from_end..].copy_from_slice(&bitlength.to_be_bytes());

        res
    }
}

pub fn sha1_no_alloc_block_proc(
    h: &mut [u32; SHA1_LEN_BYTES / 4],
    msg_block: &[u8]
) {
    if msg_block.len() != BLOCK_LEN_BYTES {
        panic!("Message length should have been 64 bytes. Was {}", msg_block.len());
    }

    let mut a = [0u32; SHA1_LEN_BYTES / 4];
    let mut w = [0u32; 80];

    for i in 0..16 {
        w[i] = u32::from_be_bytes(msg_block[i * 4 .. (i + 1) * 4].try_into().unwrap());
    }

    for t in 16..80 {
        w[t] = s(1, w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16])
    }

    a.copy_from_slice(h);

    for t in 0..80 {
        let temp = Wrapping(s(5, a[0])) + Wrapping(f(t, a[1], a[2], a[3])) + Wrapping(a[4]) + Wrapping(w[t]) + Wrapping(k(t));
        a[4] = a[3];
        a[3] = a[2];
        a[2] = s(30, a[1]);
        a[1] = a[0];
        a[0] = temp.0;
    }

    for i in 0..5 {
        h[i] = (Wrapping(h[i]) + Wrapping(a[i])).0;
    }
}

pub fn sha1(content: &dyn Sha1able) -> Vec<u8> {
    let padded = content.sha1pad();
    println!("{:?}", padded);
    let mut res = vec![0u8; SHA1_LEN_BYTES];
    let mut h = [
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0
    ];

    for i in 0..padded.len() / BLOCK_LEN_BYTES {
        sha1_no_alloc_block_proc(&mut h, &padded[i * BLOCK_LEN_BYTES..(i + 1) * BLOCK_LEN_BYTES]);
    }

    for i in 0..h.len() {
        res[i * 4..(i + 1) * 4].copy_from_slice(&h[i].to_be_bytes());
    }

    res
}

fn k(t: usize) -> u32 {
    match t {
        0..=19 => return 0x5A827999,
        20..=39 => return 0x6ED9EBA1,
        40..=59 => return 0x8F1BBCDC,
        60..=79 => return 0xCA62C1D6,
        _ => panic!("sha1.rs: `t` out of range in `K` t={}", t)
    }
}

fn s(n: usize, x: u32) -> u32 {
    (x << n) | (x >> (32 - n))
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
        let expected_usize = vec![
            0x61, 0x62, 0x63, 0x64, 0x65, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28,
        ];

        assert_eq!(
            &input.sha1pad(),
            &expected_usize
        )
    }

    #[test]
    fn test_sha1() {
        assert_eq!(hex::encode(sha1(&vec![0u8; 0])), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }
}
