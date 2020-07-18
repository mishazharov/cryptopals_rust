extern crate hex;
extern crate base64;

pub fn hex_arr_from_str(content: &str) -> Vec<Vec<u8>> {
    let split_contents: Vec<&str> = content.split('\n').collect();

    let bytes_vecs: Vec<Vec<u8>> = split_contents.iter().map(
        |x| hex::decode(x).unwrap()
    ).collect();
    bytes_vecs
}

pub fn base64_from_str(content: &str) -> Vec<u8> {
    let base64_string: String = content.split_whitespace().collect();
    let raw_bytes: Vec<u8> = base64::decode(&base64_string).unwrap();
    raw_bytes
}
