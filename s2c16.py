#Cryptopals Challenge 16
from s2c10 import encrypt_AES_CBC_128, decrypt_AES_CBC_128
from random import randint

def join_bufs(bufs):
    output = bytearray()
    for i in bufs:
        output.extend(i)
    return bytes(output)

#ORACLE FUNCTIONS
def oracle_16_a(aes_key,init_vector):
    oracle_pre = "comment1=cooking%20MCs;userdata=".encode("utf-8")
    oracle_suf = ";comment2=%%20like%%20a%20pound%%20of%%20bacon".encode("utf-8")
    return lambda x : encrypt_AES_CBC_128(join_bufs([oracle_pre, x, oracle_suf]), aes_key, init_vector)

def oracle_16_b(aes_key,init_vector):
    return lambda x : check_win(decrypt_AES_CBC_128(x, aes_key, init_vector))

def check_win(plain_text):
    target_substring = ";admin=true;"
    ptr = 0
    for c in plain_text:
        if c == ord(target_substring[ptr]):
            ptr += 1
            if ptr == len(target_substring):
                return True
            continue
        ptr = 0
    return False

#Oracle-generation function.
def generate_oracles():
    #Generate AES key
    challenge_key = bytes([randint(0,255) for i in range(16)])
    challenge_iv= bytes([randint(0,255) for i in range(16)])
    
    #Generate actual oracles
    oracle_a = oracle_16_a(challenge_key, challenge_iv)
    oracle_b = oracle_16_b(challenge_key, challenge_iv)

    #Return the two oracles
    return [oracle_a, oracle_b]

#Buffer xor-ing function.
'''
Gonna be honest here, I actually like functional programming just a little bit.
While being difficult to work with at times, it is very satisfying to write for
cryptography problems.
'''
def buf_xor(a, b):
    return bytes([(a[i] ^ b[i] if i < len(b) else a[i]) for i in range(len(a))])if len(a) >= len(b) else buf_xor(a,b)

#Attack function
def attack(oracle):
    #Generate base
    payload = bytes([0 for i in range(16)])
    oracle_base = bytearray(oracle(payload))

    target_string = ";admin=true;"
    for i in range(len(target_string)):
        oracle_base[i + 16] = oracle_base[i + 16] ^ ord(target_string[i])
    
    return bytes(oracle_base)

#Challenge code
if __name__ == "__main__":

    #Get the oracles
    chall_a, chall_b = generate_oracles()

    #Run challenge and print result
    sliced_message = attack(chall_a)
    print("CORRECT" if chall_b(sliced_message) else"WRONG" )

    print("--- CHALLENGE STATUS: COMPLETE ---")
