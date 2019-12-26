
def fixed_xor(bytes_1, bytes_2):
    if len(bytes_1) != len(bytes_2):
        raise ValueError("Byte arguments are not the same length")

    res_int = int.from_bytes(bytes_1, byteorder='big') ^ int.from_bytes(bytes_2, byteorder='big')
    return int.to_bytes(res_int, res_int.bit_length() // 8 + 1, 'big')

if __name__ == "__main__":
    bytes_1 = bytearray.fromhex("1c0111001f010100061a024b53535009181c")
    bytes_2 = bytearray.fromhex("686974207468652062756c6c277320657965")
    res = fixed_xor(bytes_1, bytes_2)
    print(res.hex())
