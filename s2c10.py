#AES-CBC Implementation

#Imports
from base64 import b64decode
from s1c7 import encrypt_block_128, decrypt_block_128, trim_padding, pad_block

#Main Encryption Function for CBC mode
def encrypt_AES_CBC_128(data: bytes, aes_key: bytes, iv: bytes) -> bytes:
    output = bytearray()
    padded = False
    while not padded:
        if len(data) < 16:
            data = pad_block(data)
            padded = True
        #These statements carefully arranged for memory optimization
        iv = bytes([data[i] ^ iv[i] for i in range(16)]) #XOR
        data = data[16:] #Consume
        iv = encrypt_block_128(iv, aes_key) #Encrypt
        output.extend(iv) #Append
    return bytes(output)

#Main Decryption Functions
def decrypt_AES_CBC_128(data: bytes, aes_key: bytes, iv: bytes) -> bytes:
    output = bytearray()
    while len(data) > 0:
        plain_block = decrypt_block_128(data[:16], aes_key)
        plain_block = bytes([iv[i] ^ plain_block[i] for i in range(16)])
        iv, data = data[:16], data[16:]
        if len(data) == 0: #Trim Last block
            plain_block = trim_padding(plain_block)
        output.extend(plain_block)
    return bytes(output)

#Main
if __name__ == "__main__":
    with open("challenge-data/10.txt") as f:
        ciphertext = bytearray()
        for l in f.readlines():
            ciphertext.extend(b64decode(l.strip()))
        ciphertext = bytes(ciphertext) #Casting it for my own satisfaction/comfort
        KEY = bytes("YELLOW SUBMARINE","utf-8")
        IV = bytes([0 for _ in range(16)])
        plain_bytes = decrypt_AES_CBC_128(ciphertext, KEY, IV)
        print(plain_bytes.decode("ascii"))
    print("--- CHALLENGE COMPLETE ---")