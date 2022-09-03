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
        new_block = bytes([data[i] ^ iv[i] for i in range(16)])
        iv = encrypt_block_128(new_block, aes_key)
        output.extend(iv)
        data = data[16:]
    return bytes(output)

#Main Decryption Functions
def decrypt_AES_CBC_128(data: bytes, aes_key: bytes, iv: bytes) -> bytes:
    output = bytearray()
    while len(data) > 0:
        plain_block = decrypt_block_128(data[:16], aes_key)
        plain_block = (bytes([iv[i] ^ plain_block[i] for i in range(16)]))
        iv = data[:16]
        data = data[16:]
        if len(data) == 0: #Trim Last block
            plain_block = trim_padding(plain_block)
        output.extend(plain_block)
    return bytes(output)

    
def retrieve_data(filename):
    '''(string) -> bytes'''
    f = open(filename, "r")
    ls = f.readlines()
    f.close()
    
    output = bytearray()
    
    for line in ls:
        output.extend(b64decode(line.strip()))
    return bytes(output)

#Main Function:
def challenge():
    ciphertext = retrieve_data("10.txt")
    KEY = bytes("YELLOW SUBMARINE","utf-8")
    IV = bytes([0 for i in range(16)])
    plain_bytes = decrypt_AES_CBC_128(ciphertext, KEY, IV)
    print(plain_bytes.decode("ascii"))

DOING_CHALLENGE = True

if __name__ == "__main__":
    if DOING_CHALLENGE:
        challenge()
        