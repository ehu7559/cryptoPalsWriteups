#Challenge 2

#Converts the two hexadecimal strings to bytes and XORs them
def hex_xor(a_hex: str, b_hex: str) -> bytes:
    return buf_xor(bytes.fromhex(a_hex), bytes.fromhex(b_hex))

#Bitwise XOR for two buffers
def buf_xor(a: bytes, b: bytes) -> bytes:
    return bytes([(x ^ y) for x, y in zip(a, b)])


'''the kid don't play'''
if __name__ == "__main__":
    print(hex_xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965").decode("ascii"))
    print("--- CHALLENGE STATUS: COMPLETE ---")