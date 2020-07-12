use crate::hashing::hash_padding::*;
use std::convert::TryInto;
use std::num::Wrapping;

const MD4_LEN_BYTES: usize = 16;

pub fn md4_process_block(h: &mut [u32; MD4_LEN_BYTES / 4], msg_block: &[u8]) {
    if msg_block.len() != HASH_BLOCK_LEN_BYTES {
        panic!(
            "Message length should have been 64 bytes. Was {}",
            msg_block.len()
        );
    }

    let mut x = [0u32; 16];
    for j in 0..16 {
        x[j] = u32::from_le_bytes(msg_block[j * 4..j * 4 + 4].try_into().unwrap());
    }

    let aa = *h;

    // Beautiful
    h[0] = ff(h[0], h[1], h[2], h[3], x[0], 3);
    h[3] = ff(h[3], h[0], h[1], h[2], x[1], 7);
    h[2] = ff(h[2], h[3], h[0], h[1], x[2], 11);
    h[1] = ff(h[1], h[2], h[3], h[0], x[3], 19);
    h[0] = ff(h[0], h[1], h[2], h[3], x[4], 3);
    h[3] = ff(h[3], h[0], h[1], h[2], x[5], 7);
    h[2] = ff(h[2], h[3], h[0], h[1], x[6], 11);
    h[1] = ff(h[1], h[2], h[3], h[0], x[7], 19);
    h[0] = ff(h[0], h[1], h[2], h[3], x[8], 3);
    h[3] = ff(h[3], h[0], h[1], h[2], x[9], 7);
    h[2] = ff(h[2], h[3], h[0], h[1], x[10], 11);
    h[1] = ff(h[1], h[2], h[3], h[0], x[11], 19);
    h[0] = ff(h[0], h[1], h[2], h[3], x[12], 3);
    h[3] = ff(h[3], h[0], h[1], h[2], x[13], 7);
    h[2] = ff(h[2], h[3], h[0], h[1], x[14], 11);
    h[1] = ff(h[1], h[2], h[3], h[0], x[15], 19);

    h[0] = gg(h[0], h[1], h[2], h[3],  x[0],  3);
    h[3] = gg(h[3], h[0], h[1], h[2],  x[4],  5);
    h[2] = gg(h[2], h[3], h[0], h[1],  x[8],  9);
    h[1] = gg(h[1], h[2], h[3], h[0], x[12], 13);
    h[0] = gg(h[0], h[1], h[2], h[3],  x[1],  3);
    h[3] = gg(h[3], h[0], h[1], h[2],  x[5],  5);
    h[2] = gg(h[2], h[3], h[0], h[1],  x[9],  9);
    h[1] = gg(h[1], h[2], h[3], h[0], x[13], 13);
    h[0] = gg(h[0], h[1], h[2], h[3],  x[2],  3);
    h[3] = gg(h[3], h[0], h[1], h[2],  x[6],  5);
    h[2] = gg(h[2], h[3], h[0], h[1], x[10],  9);
    h[1] = gg(h[1], h[2], h[3], h[0], x[14], 13);
    h[0] = gg(h[0], h[1], h[2], h[3],  x[3],  3);
    h[3] = gg(h[3], h[0], h[1], h[2],  x[7],  5);
    h[2] = gg(h[2], h[3], h[0], h[1], x[11],  9);
    h[1] = gg(h[1], h[2], h[3], h[0], x[15], 13);

    h[0] = hh(h[0], h[1], h[2], h[3], x[0], 3);
    h[3] = hh(h[3], h[0], h[1], h[2], x[8], 9);
    h[2] = hh(h[2], h[3], h[0], h[1], x[4], 11);
    h[1] = hh(h[1], h[2], h[3], h[0], x[12], 15);
    h[0] = hh(h[0], h[1], h[2], h[3], x[2], 3);
    h[3] = hh(h[3], h[0], h[1], h[2], x[10], 9);
    h[2] = hh(h[2], h[3], h[0], h[1], x[6], 11);
    h[1] = hh(h[1], h[2], h[3], h[0], x[14], 15);
    h[0] = hh(h[0], h[1], h[2], h[3], x[1], 3);
    h[3] = hh(h[3], h[0], h[1], h[2], x[9], 9);
    h[2] = hh(h[2], h[3], h[0], h[1], x[5], 11);
    h[1] = hh(h[1], h[2], h[3], h[0], x[13], 15);
    h[0] = hh(h[0], h[1], h[2], h[3], x[3], 3);
    h[3] = hh(h[3], h[0], h[1], h[2], x[11], 9);
    h[2] = hh(h[2], h[3], h[0], h[1], x[7], 11);
    h[1] = hh(h[1], h[2], h[3], h[0], x[15], 15);

    for i in 0..4 {
        h[i] = (Wrapping(h[i]) + Wrapping(aa[i])).0;
    }
}

pub fn md4(data: &dyn HashPaddable) -> Vec<u8> {
    let mut h: [u32; MD4_LEN_BYTES / 4] = [
        0x67452301,
        0xefcdab89,
        0x98badcfe,
        0x10325476
    ];

    let padded = data.hashpad(false);

    for i in 0..padded.len() / HASH_BLOCK_LEN_BYTES {
        md4_process_block(
            &mut h,
            &padded[i * HASH_BLOCK_LEN_BYTES..(i + 1) * HASH_BLOCK_LEN_BYTES],
        );
    }

    h.iter().map(|x| x.to_le_bytes().to_vec()).flatten().collect()
}

fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | ((!x) & z)
}

fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn ff(a: u32, b: u32, c: u32, d: u32, k: u32, ss: usize) -> u32 {
    return s(ss, (Wrapping(a) + Wrapping(f(b,c,d)) + Wrapping(k)).0);
}

fn gg(a: u32, b: u32, c: u32, d: u32, k: u32, ss: usize) -> u32 {
    return s(ss, (Wrapping(a) + Wrapping(g(b, c, d)) + Wrapping(k) + Wrapping(0x5A827999)).0);
}

fn hh(a: u32, b: u32, c: u32, d: u32, k: u32, ss: usize) -> u32 {
    return s(ss, (Wrapping(a) + Wrapping(h(b, c, d)) + Wrapping(k) + Wrapping(0x6ED9EBA1)).0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{distributions::Standard, self, Rng};
    use md4::{Md4, Digest};

    fn t_md4(data: &[u8]) -> Vec<u8> {
        let mut hasher = Md4::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    #[test]
    fn test_sha4_random() {
        for i in 0..500 {
            let rng = rand::thread_rng();
            let data: Vec<u8> = rng
                .sample_iter(Standard)
                .take(i)
                .collect();

            assert_eq!(
                t_md4(&data),
                &md4(&data)[..],
                "data {}",
                data.iter().map(|x| format!("{:#04x}, ", x)).collect::<String>()
            );
        }
    }
}
