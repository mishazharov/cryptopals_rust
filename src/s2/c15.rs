fn padding_validation(to_validate: &[u8]) -> Result<&[u8], &'static str> {
    let len_slice = to_validate.len();
    let len_padding: u8 = match len_slice {
        0 => return Err("Empty string does not have a well defined padding"),
        n => to_validate[n - 1]
    };

    let mut count: usize = 0;
    loop {
        if len_slice - 1 < count {
            return Err("No content found")
        }

        let curr_ind: usize = len_slice - count - 1;

        if to_validate[curr_ind] != len_padding {
            return Err("Invalid padding")
        }

        count += 1;

        if count >= len_padding as usize {
            return Ok(&to_validate[0..len_slice - len_padding as usize])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_valid_padding() {
        assert_eq!(padding_validation("ICE ICE BABY\x04\x04\x04\x04".as_bytes()).unwrap(), "ICE ICE BABY".as_bytes());
    }

    #[test]
    fn test_invalid_padding() {
        assert_eq!(padding_validation("ICE ICE BABY\x05\x05\x05\x05".as_bytes()), Err("Invalid padding"));
    }

    #[test]
    fn test_invalid_padding_2() {
        assert_eq!(padding_validation("ICE ICE BABY\x01\x02\x03\x04".as_bytes()), Err("Invalid padding"));
    }

    #[test]
    fn test_invalid_padding_3() {
        assert_eq!(padding_validation("\x04\x04\x04".as_bytes()), Err("No content found"));
    }
}
