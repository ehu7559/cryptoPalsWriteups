#Challenge 17: CBC Padding Oracle Attack

#Imports
from base64 import b64decode
from s2c9 import trim_padding
from s2c10 import AES_CBC_128 as CBC
from s2c14 import cipher_blocks
from s2c15 import is_valid_CBC_padding
from s2c16 import join_bufs
from random import randint, choice

#Padding Oracle (In a real attack this would send a request and judge by server response)
def get_padding_oracle(aes_key: bytes):
    return lambda ct, iv : is_valid_CBC_padding(ct, aes_key, iv)

def apply_iv(a: bytes, b: bytes) -> bytes:
    return bytes([(a[i] ^ b[i]) for i in range(len(a))])

#Attack Helper (Actually conducts the attack)
def attack_block(oracle, block: bytes) -> bytes:
    #Initialize brute-force procedure    
    zeroing_iv = bytearray(16)
    output = bytearray(16)

    #For each of the bytes
    for i in range(15, -1, -1): #Counts back from 15
        pad_length = 16 - i
        #modify previous bytes to get proper zeroing iv
        for j in range(i + 1, 16):
            #Modify the zeroing IV => OUTPUT ^ NEW PAD LENGTH
            zeroing_iv[j] = output[j]  ^ pad_length
        #Search through byte possibilities
        while not oracle(block, zeroing_iv):
            zeroing_iv[i] = (zeroing_iv[i] + 1) % 256 #increment with mod.

        #Add it to the output
        output[i] =  pad_length ^ zeroing_iv[i]
        
    return output

#Main Attack Loop
def attack(oracle, ciphertext: bytes, init_vector: bytes) -> bytes:
    #Break it into blocks.
    ct_blocks = cipher_blocks(ciphertext)
    pt_blocks = []
    iv_blocks = [init_vector] #The corresponding initialization vectors

    #load more initialization vectors
    iv_blocks.extend(ct_blocks)
    iv_blocks.pop() #Don't need last block (it's not used as an IV)

    #Process each attack individually
    #This is trivial to prove correct.
    for i in range(len(ct_blocks)):
        pt_blocks.append(apply_iv(attack_block(oracle, ct_blocks[i]), iv_blocks[i]))

    #Join and return output
    return trim_padding(join_bufs(pt_blocks))

#TODO: move choose_text() and get_challenge() functions to __main__.
def choose_text() -> bytes:
    with open("challenge-data/17.txt", "r") as f:
        return bytes(b64decode(choice(f.readlines()).strip()))

def get_challenge() -> tuple:
    #Generate key
    chall_key = bytes([randint(0,255) for _ in range(16)])
    chall_iv = bytes([randint(0,255) for _ in range(16)])
    chall_txt = choose_text()

    print("TARGET: " + chall_txt.decode('ascii'))
    #Encrypt text
    ciphertext = CBC.encrypt(chall_txt, chall_key, chall_iv)

    #Create Oracle
    chall_oracle = get_padding_oracle(chall_key)

    #Return ciphertext, iv, and oracle
    return (ciphertext, chall_iv, chall_oracle)
    
#CHALLENGE CODE:
if __name__ == "__main__":
    chall_ct, chall_iv, chall_o = get_challenge()
    plain_text = attack(chall_o, chall_ct, chall_iv)
    print("RESULT: " + plain_text.decode("utf-8"))
    print("--- CHALLENGE STATUS: COMPLETE ---")