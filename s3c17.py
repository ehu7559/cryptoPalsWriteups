#CBC Padding Oracle Attack

#Imports
from s2c14 import cipher_blocks
from s2c10 import encrypt_AES_CBC_128, decrypt_AES_CBC_128
from s2c15 import valid_pad
from s2c16 import join_bufs

#Padding Oracle (In a real attack this would send a request and judge by server response)
def get_padding_oracle(aes_key):
    return lambda ct, iv : valid_pad(decrypt_AES_CBC_128(ct, aes_key, iv))

#Attack Helper (Actually conducts the attack)
def attack_block(oracle, block, iv):
    for i in range(16):
        pass
#Main Attack Loop
def attack(oracle, ciphertext, init_vector):
    #Break it into blocks.
    ct_blocks = cipher_blocks(ciphertext)
    pt_blocks = []
    iv_blocks = [init_vector] #The corresponding initialization vectors

    #load more initialization vectors
    iv_blocks.extend(ct_blocks)
    iv_blocks.pop() #Don't need last one

    #Process each attack individually
    #This is trivial to prove correct.
    for i in range(len(ct_blocks)):
        pt_blocks.append(attack_block(oracle, ct_blocks[i], iv_blocks[i]))

    #Join and return output
    return join_bufs(pt_blocks)

#CHALLENGE CODE:
if __name__ == "__main__":

    print("--- CHALLENGE STATUS: INCOMPLETE ---")