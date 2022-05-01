'''
Fixed XOR
Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c
... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965
... should produce:

746865206b696420646f6e277420706c6179
'''

def hex_xor(a_hex, b_hex):
    a = bytes.fromhex(a_hex)
    b = bytes.fromhex(b_hex) 
    return bytes([(a[i] ^ b[i]) for i in range(len(a))])


'''the kid don't play'''
if __name__ == "__main__":
    print(str(hex_xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")))
    print("--- CHALLENGE STATUS: COMPLETE ---")