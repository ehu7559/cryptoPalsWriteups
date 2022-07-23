#Recover the key from CBC with IV=Key

#Imports
from s2c10 import decrypt_AES_CBC_128
from s2c16 import  oracle_16_a

#Validation function
def is_valid_ciphertext(data, key, iv):
    plain_data = decrypt_AES_CBC_128(data, key, iv)
    for a in plain_data:
        if a not in range(127):
            return False 
    return True

#Oracle Generator
#Decryption oracle
def is_valid():
    pass

#Attack Function
def attack():
    pass

#Challenge Code
if __name__ == "__main__":
    #Create decryption oracle
    pass
