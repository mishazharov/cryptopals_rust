import base64

test_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

def hex_to_base64(hex_str):
    return base64.b64encode(bytearray.fromhex(hex_str)).decode('ascii')

if __name__ == "__main__":
    print(hex_to_base64(test_str))
