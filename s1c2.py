#Challenge 2

def hex_xor(a_hex, b_hex):
    return buf_xor(bytes.fromhex(a_hex), bytes.fromhex(b_hex))

def buf_xor(a, b):
    return bytes([(x ^ y) for x, y in zip(a,b)])


'''the kid don't play'''
if __name__ == "__main__":
    print(hex_xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965").decode("ascii"))
    print("--- CHALLENGE STATUS: COMPLETE ---")