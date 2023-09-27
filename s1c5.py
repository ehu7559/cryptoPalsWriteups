#Challenge 5: Implement repeating-key XOR

#Main functions
def encrypt(data: bytes, key: bytes) -> bytes:
    return bytes([int((data[i]) ^ (key[i % len(key)])) for i in range(len(data))])
def decrypt(data: bytes, key: bytes) -> bytes:
    return encrypt(data, key) #Decryption is equal to encryption. Thus, using alias here.

#Challenge Code
if __name__ == "__main__":
    plain_text = bytes("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal","ascii")
    ice_key = bytes("ICE", "ascii")
    print(bytes.hex(encrypt(plain_text, ice_key)))
    print("--- CHALLENGE STATUS: COMPLETE ---")