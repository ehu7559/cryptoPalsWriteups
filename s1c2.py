#Challenge 2
def xor(a, b):
    '''Generalized xor function that works on ints, hex strings, and bytes/bytearray objects. \nReturns the same type.'''
    if type(a) != type(b):
        raise Exception(f"XOR Type Mismatch ({type(a)} != {type(b)})")
    if type(a) not in (str, bytes, bytearray, int):
        raise Exception(f"XOR operation not defined for type ({type(a)})")
    if type(a) == int:
        return a ^ b
    if len(a) != len(b):
        raise Exception("Buffers mismatched in length")
    n = len(a)
    if type(a) == str:
        try:
            a, b = bytes.fromhex(a), bytes.fromhex(b)
        except ValueError:
            raise Exception("String input must be hex")
        return bytes([a[i] ^ b[i] for i in range(n)]).hex()
    if type(a) == bytearray:
        return bytearray([a[i] ^ b[i] for i in range(n)])
    else:
        return bytes([a[i] ^ b[i] for i in range(n)])

'''the kid don't play'''
if __name__ == "__main__":
    print(xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965").decode("ascii"))
    print("--- CHALLENGE STATUS: COMPLETE ---")