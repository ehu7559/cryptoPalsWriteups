from random import randint
from base64 import b64decode
from s1c7 import encrypt_AES_ECB_128
from s1c8 import probablyECB


def generate_oracle(secret_txt: bytes):
    '''Given a secret bytes object returns a function to encrypt it with variable front-padding'''

    #Generate constant key and secret-text
    secret_key = bytes([(randint(0,255)) for _ in range(16)])
    secret_txt = bytes(secret_txt)
    return (lambda atk : encrypt_AES_ECB_128(b''.join([atk,secret_txt]),secret_key))

def is_oracle_ECB(target) -> bool:
    return probablyECB(target(bytes("A" * 256, "ascii")))

def get_oracle_block_size(target) -> int:
    '''Computes the block size of a target oracle'''
    initial_length = len(target(bytes(0)))
    extender = 0
    while len(target(bytes(extender))) == initial_length:
        extender += 1
    return len(target(bytes(extender))) - initial_length
    #^ I fixed this yet again. I was stupid and used the Extended Euclidian
    #Algorithm to do it before. I am, at times, a bit of an idiot.
    #Increments the length of the input until a new block is added.
    #uses null buffers to save space in the code.

def enum_oracle(header: bytes, target_oracle, desired_block: bytes):
    for i in range(256):
        ith_plain = b''.join([header, bytes([i])])
        ith_block = extract_block(target_oracle(ith_plain), 0, len(header) + 1)
        if ith_block == desired_block:
            return i
    return 0

def extract_block(data: bytes, index: int, size=16) -> bytes:
    return bytes(data[index * size: (index + 1) * size])
    
def attack_ECB_oracle(target) -> bytes:
    '''Obtains secret of a target oracle'''
    
    #Declare output as bytearray (to append to)
    output = bytearray()
    
    #Get the block size and number of blocks. We pad with nulls uwu
    target_block_size = get_oracle_block_size(target)
    num_blocks= len(target(bytes())) // target_block_size
    
    #COMPUTE ALL THE POSSIBLE PADDING ATTACKS:
    #the ith padded_cipher is attack with i bytes of padding. Just short of a block.
    padded_ciphers = []
    for i in range(target_block_size):
        padded_ciphers.append(target(bytearray(i)))
    
    #Sliding window of last 15 bytes
    window = bytearray(target_block_size - 1)
    #For every block
    for i in range(num_blocks):
        for j in range(target_block_size):
            #block index is i
            #padding size should be (target_block_size - (j + 1))
            pad_size = (target_block_size - (j + 1))
            
            #Find the target for the enumerator.
            desired_block = extract_block(padded_ciphers[pad_size], i, target_block_size)

            #GET THE OUTPUT BYTE: 
            new_byte = enum_oracle(window, target, desired_block)

            #Push the byte to the end of the window
            window.pop(0)
            window.append(new_byte)
            
            #Append the byte to the output
            output.append(new_byte)
            print(chr(new_byte), end='')
    
    #Trim it down
    end_pad_size = output[-1]
    for i in range(end_pad_size):
        output.pop()
    
    return bytes(output)
    
if __name__ == "__main__":
    challenge_oracle = generate_oracle(b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"))
    plain_guess = attack_ECB_oracle(challenge_oracle)
    print(plain_guess.decode("ascii"))
    print("--- CHALLENGE STATUS: COMPLETE ---")