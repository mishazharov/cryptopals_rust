use std::error::Error;

pub fn pad_pkcs7(bytes: &[u8], block_size: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut res = bytes.to_vec();

    // No padding required
    let mod_block_size = bytes.len() % block_size;
    if mod_block_size == 0 {
        return Ok(res);
    }

    let required_bytes = block_size - mod_block_size;

    if required_bytes >= 256 {
        return Err(From::from("Failed to pad, block requires more than 255 bytes"));
    }

    let mut new_bytes: Vec<u8> = vec![required_bytes as u8; required_bytes];
    res.append(&mut new_bytes); 
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs7_padding_4() {
        let data = b"YELLOW SUBMARINE";
        let block_size = 20;
        assert_eq!(
            pad_pkcs7(data, block_size).unwrap(),
            b"YELLOW SUBMARINE\x04\x04\x04\x04"
        );
    }

    #[test]
    fn test_pkcs7_padding_0() {
        let data = b"YELLOW SUBMARINE";
        let block_size = 16;
        assert_eq!(
            pad_pkcs7(data, block_size).unwrap(),
            b"YELLOW SUBMARINE"
        );
    }

    #[test]
    fn test_pkcs7_padding_8() {
        let data = b"YELLOW SUBMARINE";
        let block_size = 8;
        assert_eq!(
            pad_pkcs7(data, block_size).unwrap(),
            b"YELLOW SUBMARINE"
        );
    }

    #[test]
    fn test_pkcs7_padding_12() {
        let data = b"YELLOW SUBMARINE";
        let block_size = 12;
        assert_eq!(
            pad_pkcs7(data, block_size).unwrap(),
            b"YELLOW SUBMARINE\x08\x08\x08\x08\x08\x08\x08\x08"
        );
    }
}
