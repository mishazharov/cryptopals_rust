from copy import deepcopy
from typing import List
import string

def single_byte_xor(bytes_1: bytearray, single_byte: bytearray) -> bytearray:
    res = deepcopy(bytes_1)
    for i in range(len(res)):
        res[i] ^= single_byte
    return res

score_dict = {
    'e': 12.702,
    't': 9.356,
    'a': 8.167,
    'o': 7.507,
    'i': 6.966,
    'n': 6.749,
    's': 6.327,
    'h': 6.094,
    'r': 5.987,
    'd': 4.253,
    'l': 4.025,
    'u': 2.758,
    'w': 2.560,
    'm': 2.406,
    'f': 2.228,
    'c': 2.202,
    'g': 2.015,
    'y': 1.994,
    'p': 1.929,
    'b': 1.492,
    'k': 1.292,
    'v': 0.978,
    'j': 0.153,
    'x': 0.150,
    'q': 0.095,
    'z': 0.077
}

def score_bytearray(arr: bytearray) -> int:
    res = 0
    space = False

    try:
        arr = arr.decode('ascii')
    except:
        return 0

    for i in arr:
        if i not in string.printable:
            return 0
        res += score_dict.get(i.lower(), 0)

    return res

def get_char_xor_arr(arr: bytearray) -> List[bytearray]:
    cand_arr = []
    for i in range(256):
        res = single_byte_xor(arr, i)

        res_score = score_bytearray(res)

        cand_arr.append((res, res_score, i))
    return cand_arr

if __name__ == '__main__':

    cand_arr = []

    with open('4.txt', 'r') as file:
        lines = file.readlines()
        for line in lines:
            line = bytearray.fromhex(line)
            cand_arr += get_char_xor_arr(line)
    cand_arr.sort(key=lambda b: b[1])

    print(cand_arr[-1][0].decode('ascii'))
