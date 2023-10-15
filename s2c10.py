#AES-CBC Implementation

#Imports
from base64 import b64decode
from s1c7 import AES_primitives
#Main Encryption Function for CBC mode
class AES_CBC_128:
    def encrypt(data: bytes, aes_key: bytes, iv: bytes) -> bytes:
        output = bytearray()
        padded = False
        round_keys = AES_primitives.get_round_keys(aes_key)
        while not padded:
            if len(data) < 16:
                data = AES_primitives.pad_block(data)
                padded = True
            #These statements carefully arranged for memory optimization
            iv = bytes([data[i] ^ iv[i] for i in range(16)]) #XOR
            data = data[16:] #Consume
            iv = AES_primitives.ARK(iv, round_keys[0])
            for i in range(1,10): iv = AES_primitives.encrypt_round(iv, round_keys[i])
            iv = (AES_primitives.encrypt_final_round(iv, round_keys[10]))
            output.extend(iv)
        return bytes(output)

    #Main Decryption Functions
    def decrypt(data: bytes, aes_key: bytes, iv: bytes) -> bytes:
        output = bytearray()
        round_keys = AES_primitives.get_round_keys(aes_key)
        while len(data) > 0:
            #Decrypt
            plain_block = AES_primitives.ARK(data[:16], round_keys[10])
            for i in range(9,0,-1): plain_block = AES_primitives.decrypt_round(plain_block, round_keys[i]) 
            plain_block = AES_primitives.decrypt_final_round(plain_block, round_keys[0])
            
            #XOR
            plain_block = bytes([iv[i] ^ plain_block[i] for i in range(16)])
            
            #Consume
            iv, data = data[:16], data[16:]
            #Trim
            if len(data) == 0: plain_block = AES_primitives.trim_padding(plain_block)
            output.extend(plain_block)
        return bytes(output)

#Main
if __name__ == "__main__":
    with open("challenge-data/10.txt") as f:
        ciphertext = b64decode("".join([l.strip() for l in f.readlines()]))
        KEY = bytes("YELLOW SUBMARINE","utf-8")
        IV = bytes(16)
        plain_bytes = AES_CBC_128.decrypt(ciphertext, KEY, IV)
        print(plain_bytes.decode("ascii"))
    print("--- CHALLENGE COMPLETE ---")