#Challenge 14

#Import modules
from random import randint
from base64 import b64decode
from s1c7 import encrypt_AES_ECB_128

#Generate Class 14 ECB Oracle
def gen_oracle_14(secret_text):
    #Generate Oracle Constants
    secret_key = bytes([randint(0,255) for i in range(16)])
    prefix_len = random.randint(0,255)
    
    #

#Oracle prefix length determination
def get_oracle_prefix_len(oracle):
    pass
    
#Pseudo-oracle
def pseudo_oracle(oracle):
    #Get length of prefix through get_oracle_prefix_len
    
    #Generate new lambda function by padding and splicing.
    
    pass
#Attacker
def attack_oracle(oracle):
    '''Obtains secret of a target oracle'''
    target = pseudo_oracle(oracle)
    
    #Declare output as bytearray (to append to)
    output = bytearray()
    
    #Get the block size and number of blocks. We pad with nulls uwu
    target_block_size = 16
    num_blocks= len(target(bytes())) // target_block_size
    
    #COMPUTE ALL THE POSSIBLE PADDING ATTACKS:
    #the ith padded_cipher is attack with i bytes of padding. Just short of a block.
    padded_ciphers = []
    for i in range(target_block_size):
        padded_ciphers.append(target(bytearray(i)))
    print("SECRET LENGTH: " + str(len(padded_ciphers[0])))
    window = bytearray(target_block_size - 1)
    #For every block
    for i in range(num_blocks):
        #print("BLOCKS DECRYPTED: " + str(i))
        for j in range(target_block_size):
            #print("\tBYTE: " + str(j))
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
    
    #Trim it down
    end_pad_size = output[-1]
    for i in range(end_pad_size):
        output.pop()
    
    return bytes(output)
    #Return
#Challenge code
if __name__ == "__main__":
    #Generate Oracle
    
    #Attack the Oracle
    
    #End
    print("--- CHALLENGE INCOMPLETE ---")