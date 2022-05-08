#CBC Padding Oracle Attack

#Imports
import base64
from s2c14 import cipher_blocks
from s2c10 import encrypt_AES_CBC_128, decrypt_AES_CBC_128
from s2c15 import valid_pad
from s2c16 import join_bufs
from random import randint, choice

#Padding Oracle (In a real attack this would send a request and judge by server response)
def get_padding_oracle(aes_key):
    return lambda ct, iv : valid_pad(decrypt_AES_CBC_128(ct, aes_key, iv))

def apply_iv(a, b):
    return bytes([(a[i] ^ b[i]) for i in range(len(a))])

#Attack Helper (Actually conducts the attack)
def attack_block(oracle, block):
    #Initialize brute-force procedure    
    zeroing_iv = bytearray(16)
    output = bytearray(16)
    desired_pad_len = 1
    
    #For each of the bytes
    for i in range(15, -1, -1): #Coutns back from 15
        #modify previous bytes to get proper zeroing iv
        for j in range(i, 16):
            zeroing_iv[j] = output[j] ^ i
        
        #Search through byte possibilities
        while not oracle(block, zeroing_iv):
            zeroing_iv[i] = (zeroing_iv[i] + 1) % 256 #increment with mod.
                    
        #Check for edge cases (1/256 chance but i'm not taking it)
        if i == 15:
            pass
    
    return output

#Main Attack Loop
def attack(oracle, ciphertext, init_vector):
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
    return join_bufs(pt_blocks)

def choose_text():
    with open("17.txt", "r") as f:
        return bytes(base64.b64decode(choice(f.readlines())))

def get_challenge():
    #Generate key
    chall_key = bytes([randint(0,255) for i in range(16)])
    chall_iv = bytes([randint(0,255) for i in range(16)])

    #Encrypt text
    ciphertext = encrypt_AES_CBC_128(choose_text(), chall_key, chall_iv)

    #Create Oracle
    chall_oracle = get_padding_oracle(chall_key)

    #Return ciphertext, iv, and oracle
    return [ciphertext, chall_iv, chall_oracle]

#CHALLENGE CODE:
if __name__ == "__main__":
    chall_ct, chall_iv, chall_o = get_challenge()
    attack(chall_o, chall_ct, chall_iv)
    print("--- CHALLENGE STATUS: INCOMPLETE ---")