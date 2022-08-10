#AES-CBC Implementation

#Imports
from base64 import b64decode
from s1c7 import get_pad, encrypt_block_128, decrypt_block_128

#Main Encryption Function for CBC mode
def encrypt_AES_CBC_128(data: bytes, aes_key: bytes, initialization_vector: bytes) -> bytes:
    output = bytearray()
    pad = get_pad(len(data))
    working = bytearray()
    iv = bytes(initialization_vector)
    for b in data:
        working.append(b) #I thought about xoring bitwise here, but len() may be slow.
        if len(working) == 16:
            xored = bytes([(working[i] ^ iv[i]) for i in range(16)]) #CBC XOR
            iv = bytes(encrypt_block_128(xored , aes_key))
            output.extend(iv)
            working = bytearray()
            
    working.extend(pad) #Pad for final block
    xored_end = bytes([(working[i] ^ iv[i]) for i in range(16)])
    output.extend(encrypt_block_128(xored_end, aes_key))
    return bytes(output)

#Main Decryption Functions
def decrypt_AES_CBC_128(data: bytes, aes_key: bytes, initialization_vector: bytes) -> bytes:

    #BLOCKS: Much more efficient thanks to known block parity
    num_blocks = len(data)//16
    output = bytearray()
    iv = bytes(initialization_vector)
    vectors = [iv]
    vectors.extend([bytes(data[16 * i: 16 * (i + 1)]) for i in range(num_blocks)])
    #Decrypt
    for i in range(num_blocks):
        #decrypt
        plainx = decrypt_block_128(vectors[i+1], aes_key)
        #xor with vectors[i]
        plain = bytes([(plainx[x] ^ (vectors[i])[x])for x in range(16)])

        #append to output
        output.extend(plain)
    #Return
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
        