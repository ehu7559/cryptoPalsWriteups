#Challenge 18

#Imports
from base64 import b64decode
from s1c7 import encrypt_AES_ECB_128

#Block Encryption Function
def gen_block(aes_key, nonce, ctr):
    
    #Prepare nonce and counter (challenge indicates little-endian uint64)
    nonce_bytes = bytearray(8)
    non = int(nonce)
    for i in range(8):
        nonce_bytes[i] = non%256
        non = non // 256
    
    counter_bytes = bytearray(8)
    count = int(ctr)
    for i in range(8):
        counter_bytes[i] = count%256
        count = count // 256
    
    block = bytearray(nonce_bytes)
    block.extend(counter_bytes)
    return encrypt_AES_ECB_128(bytes(block), aes_key)

#Keystream oracle function
def aes_ctr_keystream(aes_key, nonce):
    counter = 0
    while True:
        #Generate keystream block
        output = gen_block(aes_key, nonce, counter)

        #Compute with the 
        for i in range(16):
            yield output[i]
        counter += 1

#CTR Mode Implementation
def encrypt_AES_CTR(data, key, nonce):
    stream = aes_ctr_keystream(key, nonce)
    return bytes([i ^ next(stream) for i in data])

#Alias for compatibility
def decrypt_AES_CTR(data, key, nonce):
    return encrypt_AES_CTR(data, key, nonce)

#Challenge Code
if __name__ == "__main__":
    challenge_ciphertext = b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
    challenge_key = "YELLOW SUBMARINE".encode("utf-8")
    print(encrypt_AES_CTR(challenge_ciphertext, challenge_key, 0).decode("ascii"))
    print("--- CHALLENGE STATUS: COMPLETE ---")