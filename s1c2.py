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

def buf_xor(a_hex, b_hex):
    a_bytes = bytes.fromhex(a_hex)
    b_bytes = bytes.fromhex(b_hex)
    c_bytearr = bytearray()
    for i in range(len(a_bytes)):
        c_bytearr.append(a_bytes[i] ^ b_bytes[i])
    return bytes(c_bytearr)

'''the kid don't play'''
