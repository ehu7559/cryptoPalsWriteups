#Challenge 26: 

from random import randint
from s3c18 import AES_CTR as CTR


def get_token(username, key, nonce):
    token_string = "comment1=cooking MCs;userdata=" + username + ";comment2= like a pound of bacon"
    return CTR.encrypt(bytes([ord(c) for c in token_string]), key, nonce)

def get_oracle(key, nonce):
    return lambda x : get_token(x, key, nonce)

def check_win(token, key, nonce):
    print(CTR.encrypt(token, key, nonce).decode("ascii"))
    return "admin=true" in (CTR.encrypt(token, key, nonce)).decode("ascii").split(";")

def forge_token(oracle):
    injection = " admin true"
    start_index = len("comment1=cooking MCs;userdata=")
    token = bytearray(oracle(injection))
    token[start_index] = token[start_index] ^ ord(" ") ^ ord(";") 
    token[start_index + 6] = token[start_index + 6] ^ ord(" ") ^ ord("=")
    return bytes(token) 


if __name__ == "__main__":
    #Generate key and nonce pair
    chall_nonce = randint(0, 2**64 - 1)
    chall_key = bytes([randint(0, 255) for _ in range(16)])

    #Get oracle
    chall_oracle = get_oracle(chall_key, chall_nonce)
    chall_forged = forge_token(chall_oracle)
    
    print(f"--- CHALLENGE STATUS: {'COMPLETE' if check_win(chall_forged, chall_key, chall_nonce) else 'ERROR' } ---")