from copy import deepcopy
def single_byte_xor(bytes_1: bytearray, single_byte: bytearray) -> bytearray:
    res = deepcopy(bytes_1)
    for i in range(len(res)):
        res[i] ^= single_byte
    return res

score_dict = {
    'U': 2,
    'L': 2,
    'D': 3,
    'R': 3,
    'H': 3,
    'S': 4,
    ' ': 4,
    'N': 4,
    'I': 4,
    'O': 5,
    'A': 5,
    'T': 5,
    'E': 5,
}

def score_bytearray(arr: bytearray) -> int:
    res = 0

    for i in arr:
        i = chr(i)
        res += score_dict.get(i.upper(), 1)

    return res

if __name__ == "__main__":
    test_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    test_bytes = bytearray.fromhex(test_str)

    cand_arr = []
    for i in range(256):
        res = single_byte_xor(test_bytes, i)

        if not res.isascii():
            continue

        res_score = score_bytearray(res)

        cand_arr.append((res, res_score, i))
    cand_arr.sort(key=lambda b: b[1])

    print(cand_arr[-1][0].decode('ascii'))
