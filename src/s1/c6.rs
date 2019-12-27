use std::error::Error;

extern crate hex;

pub fn xor_bytes(str_1: &[u8], str_2: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if str_1.len() != str_2.len() {
        return Err(From::from("bytes are not of equal length"))
    }
    let mut res = vec![0; str_1.len()];
    for i in 0..str_1.len() {
        res[i] = str_1[i] ^ str_2[i]
    }
    Ok(res)
}

pub fn hamming_distance(str_1: &[u8], str_2: &[u8]) -> Result<u32, Box<dyn Error>> {
    let xored_bytes = xor_bytes(str_1, str_2)?;
    let mut res: u32 = 0;
    for i in xored_bytes {
        res += i.count_ones();
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hamming_distance() {
        assert_eq!(hamming_distance(b"this is a test", b"wokka wokka!!!").unwrap(), 37);
    }

    #[test]
    fn test_xor_bytes() {
        assert_eq!(
            xor_bytes(
                &hex::decode("1c0111001f010100061a024b53535009181c").unwrap(),
                &hex::decode("686974207468652062756c6c277320657965").unwrap()
            ).unwrap(),
            hex::decode("746865206b696420646f6e277420706c6179").unwrap()
        );
    }
}
