import random
from base64 import b64decode
from s1c7 import encrypt_AES_ECB_128
from s1c8 import probablyECB

def merge_bytes(a,b):
    output = bytearray(a)
    output.extend(b)
    return bytes(output)
    
def generate_oracle(secret_txt):
    '''Given a secret bytes object returns a function to encrypt it with variable front-padding'''

    #Generate constant key and secret-text
    secret_key = bytes([(random.randint(0,255)) for i in range(16)])
    secret_txt = bytes(secret_txt)
    return (lambda atk : encrypt_AES_ECB_128(merge_bytes(atk,secret_txt),secret_key))

def is_oracle_ECB(target):
    return probablyECB(target(bytes("A" * 256, "ascii")))

def get_oracle_block_size(target):
    '''Computes size of a target oracle
    TODO: IMPLEMENT THIS FOR REAL
    Can be done by sending progressively longer pads until the start of the
    ciphertext is exactly two cycles of a repeated block.
    '''
    return 16

def attack_enum(header, target_oracle):
    pass    

def extract_block(data, index, size):
    return bytes(data[index * size: (index + 1) * size])
    
def attack_ECB_oracle(target):
    '''Obtains secret of a target oracle'''
    
    #Checks that oracle is a function (Unnecessary but i was checking uwu)
    if str(type(target)) != "<class 'function'>":
        print("ERROR: ORACLE IS NOT A Function")
        return bytes()
    #Check that the oracle is ECB
    if not is_oracle_ECB(target):
        print("ERROR: ORACLE IS NOT ECB")
        return bytes()
    
    #Declare output as bytearray (to append to)
    output = bytearray()
    
    #Get the block size and number of blocks. We pad with nulls uwu
    target_block_size = get_oracle_block_size(target)
    num_blocks= len(target(bytes())) // target_block_size
    
    #COMPUTE ALL THE POSSIBLE PADDING LENGTHS:
    padded_ciphers = []
    for i in range(target_block_size):
        padded_ciphers.append(target(bytearray(i)))
    #the ith padded_cipher is attack with i bytes of padding. Just short of a block.
    
    output = bytearray()
    window = bytearray(target_block_size - 1)
    #For every block
    for i in range(num_blocks):
        for j in range(target_block_size):
            look_at_cipher_index = target_block_size - 1 - j
            
                
    pass
    
if __name__ == "__main__":
    challenge_oracle = generate_oracle(b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"))
    plain_guess = attack_ECB_oracle(challenge_oracle)
    print(plain_guess.decode("ascii"))