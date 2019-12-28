use std::error::Error;

extern crate hex;

pub fn xor_bytes(str_1: &[u8], str_2: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if str_1.len() != str_2.len() {
        return Err(From::from("bytes are not of equal length"))
    }
    // https://users.rust-lang.org/t/how-to-xor-two-vec-u8/31071/2
    let res: Vec<u8> = str_1.iter().zip(str_2.iter()).map(|(&x,&y)| x ^ y).collect();
    Ok(res)
}

pub fn hamming_distance(str_1: &[u8], str_2: &[u8]) -> Result<u32, Box<dyn Error>> {
    let xored_bytes: Vec<u8> = xor_bytes(str_1, str_2)?;
    let mut res: u32 = 0;
    xored_bytes.iter().for_each(|&x| res += x.count_ones());
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
