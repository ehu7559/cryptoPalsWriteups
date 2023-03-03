#Cryptopals Challenge 13
from s1c7 import encrypt_AES_ECB_128, decrypt_AES_ECB_128
from random import randint

#Parsing Routine
def parse_cookie(c: str) -> str:
    output = "{\n"
    lines = c.split("&")
    for l in lines:
        kv = l.split("=")
        output += "\t" + kv[0] + ":" + kv[1] + "\n"
    output +="}"
    return output

#ORACLE GENERATORS:

#Encryption Oracle
def profile_oracle(aes_key: bytes):
    return lambda string : encrypt_AES_ECB_128((parse_cookie("email="+string + "&uid=5&role=user")).encode("utf-8"), aes_key)
#Decryption Oracle
def decrypt_oracle(aes_key: bytes):
    return lambda x : decrypt_AES_ECB_128(x, aes_key)

def get_oracles() -> tuple:
    #Generate random key
    rand_aes_key = bytes([randint(0,255) for i in range(16)])
    
    #Generate profile oracle
    pfo = profile_oracle(rand_aes_key)
    
    #Generate decryption oracle (for checking)
    dro = decrypt_oracle(rand_aes_key)
    
    #Return the two oracles together.
    return (pfo, dro)
    
#Gain admin block
def get_admin_block(pf_oracle) -> bytes:
    #Construct attack buffer
    get_admin_str = "abcdefgadmin\n}\t\t\t\t\t\t\t\t\t"
    
    #Feed the oracle the proper attack string
    admin_cookie_crypt = pf_oracle(get_admin_str)
    
    #Grab and return the right block
    return bytes(admin_cookie_crypt[16:32])

#Get template to put admin_block right next to.
def get_profile_base(pf_oracle) -> bytes:
    #Analogous structure to get_admin_block function
    get_base_str = "abcdefghi"
    base_cookie_crypt = pf_oracle(get_base_str)
    return bytes(base_cookie_crypt[0:32])
    
#Attack Function
def attack_oracle(oracle) -> bytes:
    #Get "admin" suffix.
    ad_block = get_admin_block(oracle)
    
    #Get text to put "user" right at end of block.
    base_block = get_profile_base(oracle)
    
    output = bytearray(base_block)
    output.extend(ad_block)
    return bytes(output)
    
#CHALLENGE 13!
if __name__ == "__main__":
    
    #Create Oracles
    chall_pro, chall_dro = get_oracles()

    #Attack the profile oracle
    attack_attempt = attack_oracle(chall_pro)
    
    #Decrypt using the oracle and check
    print(chall_dro(attack_attempt).decode("utf-8"))
    #Print status of challenge
    print("--- CHALLENGE STATUS: COMPLETE ---")