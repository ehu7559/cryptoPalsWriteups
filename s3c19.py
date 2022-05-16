
#IMPORTS
from s1c6 import score_text, decrypt
from s3c18 import encrypt_AES_CTR
from random import randint
from base64 import b64decode

def safe_print(buffer, default_char=ord("*")):
    filtered_buffer = bytes([(a if a in range(32, 127) else default_char) for a in buffer])
    print(filtered_buffer.decode("ascii"))

#Oracle Generation Function
def get_crypt_oracle():
    o_key = bytes([randint(0,255) for i in range(16)])
    o_nonce = randint(0, 2**31)
    return lambda x : encrypt_AES_CTR(x, o_key, o_nonce)

def multislice(buffers, index):
    output = bytearray()
    for buf in buffers:
        if index in range(len(buf)):
            output.append(buf[index])
    return bytes(output)

def can_be_ascii(buffer):
    for a in buffer:
        if a not in range(32, 127):
            return False
    return True

#Based on an assumption that output is in ASCII
def safe_byte_crack(ciphertext):
    best_i = 0
    max_score = 0
    for i in range(256):

        #Generate the resulting plaintext
        maybe_plain = bytes([a ^ i for a in ciphertext])
        
        #Filter out the unprintables as null-candidates
        if not can_be_ascii(maybe_plain):
            continue
        
        new_score = score_text(maybe_plain)
        
        if new_score > max_score:
            best_i = i
            max_score = new_score

    return best_i
        
#Main key-attack function
def guess_key(ciphertexts):
    longest_length = len(max(ciphertexts,key=len))
    return bytes([safe_byte_crack(multislice(cipher_texts, i)) for i in range(longest_length)])

#Data retrieval function
def retrieve_lines(filename):
    with open(filename, "r") as f:
        return [b64decode(l) for l in f.readlines()]

#Challenge Code
if __name__ == "__main__":
    
    #Generate encryption oracle
    cryptoracle = get_crypt_oracle()

    #Retrieve data and process it
    cipher_texts = retrieve_lines("19.txt")

    #Attack
    chall_key_guess = bytearray(guess_key(cipher_texts))

    #Decode and encrypt each text
    for c in cipher_texts:
        #print(cryptoracle(c).decode("ascii"))
        safe_print(decrypt(c,chall_key_guess))

    print("--- CHALLENGE STATUS: COMPLETE ---")