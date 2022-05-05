#Cryptopals Challenge 16
import os

#Encrypting oracle

#Oracle-generation function.

#Buffer xor-ing function.
'''
Gonna be honest here, I actually like functional programming just a little bit.
While being difficult to work with at times, it is very satisfying to write for
cryptography problems.
'''
def buf_xor(a, b):
    return bytes([(a[i] ^ b[i] if i < len(b) else a[i]) for i in range(len(a))])if len(a) >= len(b) else buf_xor(a,b)

#Attack function
def attack(oracle):
    output = bytearray()
    return bytes(output)

#Challenge code
if __name__ == "__main__":
    print("--- CHALLENGE STATUS: INCOMPLETE ---")