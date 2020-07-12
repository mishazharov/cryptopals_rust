// An implementation of RFC3174 (https://tools.ietf.org/rfc/rfc3174.txt)
// For practicality, only bit lengths that are multiples of 8 are allowed
use std::convert::TryInto;
use std::num::Wrapping;
use crate::hashing::hash_padding::*;

pub const SHA1_LEN_BYTES: usize = 20;

pub fn sha1_process_block(h: &mut [u32; SHA1_LEN_BYTES / 4], msg_block: &[u8]) {
    if msg_block.len() != HASH_BLOCK_LEN_BYTES {
        panic!(
            "Message length should have been 64 bytes. Was {}",
            msg_block.len()
        );
    }

    let mut w = [0u32; 80];

    for i in 0..16 {
        w[i] = u32::from_be_bytes(msg_block[i * 4..(i + 1) * 4].try_into().unwrap());
    }

    for t in 16..80 {
        w[t] = s(1, w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16])
    }

    let mut a = *h;

    for t in 0..80 {
        let temp = Wrapping(s(5, a[0]))
            + Wrapping(f(t, a[1], a[2], a[3]))
            + Wrapping(a[4])
            + Wrapping(w[t])
            + Wrapping(k(t));
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

pub fn sha1(content: &dyn HashPaddable) -> Vec<u8> {
    let padded = content.hashpad(true);
    let mut h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    for i in 0..padded.len() / HASH_BLOCK_LEN_BYTES {
        sha1_process_block(
            &mut h,
            &padded[i * HASH_BLOCK_LEN_BYTES..(i + 1) * HASH_BLOCK_LEN_BYTES],
        );
    }

    h.to_vec()
        .iter()
        .flat_map(|x| x.to_be_bytes().to_vec())
        .collect()
}

fn k(t: usize) -> u32 {
    match t {
        0..=19 => return 0x5A827999,
        20..=39 => return 0x6ED9EBA1,
        40..=59 => return 0x8F1BBCDC,
        60..=79 => return 0xCA62C1D6,
        _ => panic!("sha1.rs: `t` out of range in `K` t={}", t),
    }
}

fn f(t: usize, b: u32, c: u32, d: u32) -> u32 {
    match t {
        0..=19 => return (b & c) | ((!b) & d),
        20..=39 | 60..=79 => return b ^ c ^ d,
        40..=59 => return (b & c) | (b & d) | (c & d),
        _ => panic!("sha1.rs: `t` out of range in `f` t={}", t),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand;
    use rand::distributions::Standard;
    use rand::Rng;

    #[test]
    fn test_sha1_padding_1() {
        // "abcde", right from the spec
        let input: Vec<u8> = vec![0b01100001, 0b01100010, 0b01100011, 0b01100100, 0b01100101];

        // This is terrible, but rust doesn't seems to have a clean way
        // to turn Vec<i32> => Vec<u8> (or even &[u8]) without pulling
        // in a dependency or using unsafe code.
        let expected_usize = vec![
            0x61, 0x62, 0x63, 0x64, 0x65, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28,
        ];

        assert_eq!(&input.hashpad(true), &expected_usize)
    }

    #[test]
    fn test_sha1_padding_2() {
        let input: Vec<u8> = vec![0u8; 55];
        let mut expected_out = vec![0u8; HASH_BLOCK_LEN_BYTES];
        expected_out[56..].copy_from_slice(&(55 * 8 as u64).to_be_bytes());
        expected_out[55] = 0x80;

        assert_eq!(input.hashpad(true), expected_out);
    }

    #[test]
    fn test_sha1() {
        assert_eq!(
            hex::encode(sha1(&vec![0u8; 0])),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn test_sha1_random() {
        for _ in 0..500 {
            let mut rng = rand::thread_rng();
            let data: Vec<u8> = rng
                .sample_iter(Standard)
                .take(rng.gen_range(0, 512))
                .collect();

            assert_eq!(
                &openssl::sha::sha1(&data),
                &sha1(&data)[..],
                "data {}",
                data.iter().map(|x| format!("{:#04x}, ", x)).collect::<String>()
            );
        }
    }

    #[test]
    fn test_sha1_test_vector_1() {
       let data: Vec<u8> = vec![
           0xcc, 0x26, 0x0f, 0x0c, 0x01, 0x0a, 0x4a, 0x9a,
           0xd6, 0xb9, 0x28, 0x75, 0x15, 0x04, 0x1f, 0xe6,
           0x10, 0x24, 0xb3, 0x57, 0x40, 0xb6, 0x6e, 0xbc,
           0xb0, 0xc1, 0x4c, 0x26, 0xe9, 0xa0, 0x5c, 0x43,
           0x45, 0x58, 0x80, 0xd2, 0xd6, 0x6a, 0xf8, 0xfc,
           0xc7, 0x76, 0x9e, 0xde, 0x94, 0x0b, 0x30, 0xb5,
           0x20, 0xb5, 0xc7, 0x12, 0x6d, 0xd4, 0x6b,
        ];

        assert_eq!(&openssl::sha::sha1(&data), &sha1(&data)[..]);
    }
}
