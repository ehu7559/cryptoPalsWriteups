#Cryptopals Challenge 16
from s2c10 import AES_CBC_128 as CBC
from random import randint

def join_bufs(bufs: list) -> bytes:
    output = bytearray()
    for i in bufs:
        output.extend(i)
    return bytes(output)

#ORACLE FUNCTIONS
def oracle_16_a(aes_key: bytes, init_vector: bytes):
    oracle_pre = "comment1=cooking%20MCs;userdata=".encode("utf-8")
    oracle_suf = ";comment2=%%20like%%20a%20pound%%20of%%20bacon".encode("utf-8")
    return lambda x : CBC.encrypt(join_bufs([oracle_pre, x, oracle_suf]), aes_key, init_vector)

def oracle_16_b(aes_key: bytes, init_vector: bytes): 
    return lambda x : check_win(CBC.decrypt(x, aes_key, init_vector))

def check_win(plain_text: bytes) -> bool:
    target_substring = ";admin=true;" #This inefficient checking is to accomodate the bytes type.
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
def generate_oracles() -> tuple:
    #Generate AES key
    challenge_key = bytes([randint(0,255) for i in range(16)])
    challenge_iv= bytes([randint(0,255) for i in range(16)])
    
    #Generate actual oracles
    oracle_a = oracle_16_a(challenge_key, challenge_iv)
    oracle_b = oracle_16_b(challenge_key, challenge_iv)

    #Return the two oracles
    return (oracle_a, oracle_b)
    
#Attack function
def attack(oracle) -> bytes:
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
    print("CORRECT" if chall_b(sliced_message) else "WRONG")
    print("--- CHALLENGE STATUS: COMPLETE ---")
