
#IMPORTS
from s1c3 import score_english_buffer
from s1c6 import decrypt
from s3c18 import encrypt_AES_CTR
from random import randint
from base64 import b64decode
from time import sleep

def safe_print(buffer: bytes, default_char=ord("*")):
    filtered_buffer = bytes([(a if a in range(32, 127) else default_char) for a in buffer])
    print(filtered_buffer.decode("ascii"))

#Oracle Generation Function
def get_crypt_oracle():
    o_key = bytes([randint(0,255) for _ in range(16)])
    o_nonce = randint(0, 2**31)
    return lambda x : encrypt_AES_CTR(x, o_key, o_nonce)

def multislice(buffers: bytes, index: int) -> bytes:
    output = bytearray()
    for buf in buffers:
        if index in range(len(buf)):
            output.append(buf[index])
    return bytes(output)

def can_be_ascii(buffer: bytes):
    for a in buffer:
        if a not in range(32, 127):
            return False
    return True

#Based on an assumption that output is in ASCII
def safe_byte_crack(ciphertext: bytes) -> int:
    best_i = 0
    max_score = 0
    for i in range(256):

        #Generate the resulting plaintext
        maybe_plain = bytes([a ^ i for a in ciphertext])
        
        #Filter out the unprintables as null-candidates
        if not can_be_ascii(maybe_plain):
            continue
        
        new_score = score_english_buffer(maybe_plain)
        
        if new_score > max_score:
            best_i = i
            max_score = new_score

    return best_i
        
#Main key-attack function
def guess_key(ciphertexts: bytes) -> bytes:
    longest_length = len(max(ciphertexts,key=len))
    return bytes([safe_byte_crack(multislice(ciphertexts, i)) for i in range(longest_length)])

def guess_key_demo(ciphertexts: bytes):
    longest_length = len(max(ciphertexts, key=len))
    same_slices = [multislice(ciphertexts, i) for i in range(longest_length)]
    key_guess = bytearray(longest_length)
    for i in range(longest_length):
        best_j = 0
        max_score = 0
        for j in range(256):
            key_guess[i] = j
            print(f"Cracking: {key_guess.hex()}", end="\r")
            sleep(0.005)

            #Generate the resulting plaintext
            maybe_plain = bytes([a ^ j for a in same_slices[i]])

            #Filter out the unprintables as null-candidates
            if not can_be_ascii(maybe_plain):
                continue
            
            new_score = score_english_buffer(maybe_plain)
            
            if new_score > max_score:
                best_j = j
                max_score = new_score
        key_guess[i] = best_j
    print("")
    return bytes(key_guess)

#Data retrieval function
def retrieve_lines(filename: str) -> list:
    with open(filename, "r") as f:
        return [bytes(b64decode(l)) for l in f.readlines()]

#Challenge Code
if __name__ == "__main__":
    
    #Generate encryption oracle
    cryptoracle = get_crypt_oracle()

    #Retrieve data and process it
    cipher_texts = retrieve_lines("challenge-data/19.txt")

    #Attack
    chall_key_guess = bytearray(guess_key_demo(cipher_texts))
    print(chall_key_guess)
    #Decode and encrypt each text
    for c in cipher_texts:
        #print(cryptoracle(c).decode("ascii"))
        safe_print(decrypt(c,chall_key_guess))

    print("--- CHALLENGE STATUS: COMPLETE ---")