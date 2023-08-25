#Challenge 14

#Import modules
from random import randint
from base64 import b64decode
from s1c7   import encrypt_AES_ECB_128 
from s2c12  import attack_ECB_oracle

#Generate Class 14 ECB Oracle
def gen_oracle_14(secret_text: bytes):
    #Generate Oracle Constants
    secret_key = bytes([randint(0,255) for _ in range(16)])
    secret_data = bytes(secret_text)
    prefix_len = randint(0,255)
    prefix_data = bytes([randint(0,255) for _ in range(prefix_len)])
    #Generate oracle
    return (lambda atk : encrypt_AES_ECB_128((b''.join([prefix_data, atk, secret_data])), secret_key))
    
def cipher_blocks(ciphertext: bytes) -> list:
    return [bytes(ciphertext[i * 16 : (i + 1) * 16]) for i in range(len(ciphertext)//16)]

def join_cipher(blocks: list) -> bytes:
    output = bytearray()
    for bl in blocks:
        output.extend(bl)
    return bytes(output)

#Oracle prefix length determination
def get_oracle_prefix_len(oracle) -> bytes:
    no_text = oracle(bytes())
    just_one = oracle(bytes(1))
    #Find block where it starts
    diff_ptr = 0
    while no_text[diff_ptr] == just_one[diff_ptr]:
        diff_ptr += 1
    num_full_blocks = diff_ptr // 16 #Number of full blocks in pad.
    
    #Determine how long the pad needs to be to get a block.
    two_blocks = bytes([255 for _ in range(32)])
    trailing_mod = 0
    while True:
        enum_blocks = cipher_blocks(oracle(b''.join([bytes(16 - trailing_mod), two_blocks])))
        if enum_blocks[num_full_blocks + 1] == enum_blocks[num_full_blocks + 2]:
            break
        trailing_mod += 1
    return num_full_blocks * 16 + trailing_mod

#Pseudo-oracle
def pseudo_oracle(oracle):
    #Get length of prefix through get_oracle_prefix_len
    oracle_prefix_len = get_oracle_prefix_len(oracle)
    
    #Generate new lambda function by adding more padding and splicing.
    mask_pad = bytes(16 - (oracle_prefix_len % 16))

    #Generate middle oracle.
    return (lambda x : (oracle(b''.join([mask_pad, x]))[oracle_prefix_len + len(mask_pad):]))
    
#Challenge code
if __name__ == "__main__":
    #Generate Oracle
    challenge_oracle = gen_oracle_14(b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"))
    
    #Write a proxied oracle.
    fake = pseudo_oracle(challenge_oracle)
    
    #Attack the new, prefix-less Oracle
    plain_guess = attack_ECB_oracle(fake)
    print("\n" + plain_guess.decode("ascii"))
    
    #Print challenge status
    print("--- CHALLENGE STATUS: COMPLETE ---")