#CHALLENGE 11: ECB/CBC DETECTION ORACLE

#CHALLENGE CODE
from s1c7 import AES_ECB_128 as ECB
from s2c10 import AES_CBC_128 as CBC
from s1c8 import probablyECB
from random import randint, choice

def oracle_crypt(plain_text: bytes, aes_key: bytes, init_vec: bytes, AES_mode: str) -> bytes:
    random_padding_length = randint(5,10)
    rand_pad = bytes([ord("x") for _ in range(random_padding_length)])
    
    modified_plaintext = bytearray()
    modified_plaintext.extend(rand_pad)
    modified_plaintext.extend(plain_text)
    modified_plaintext.extend(rand_pad)
    
    if AES_mode == "CBC":
        return CBC.encrypt(modified_plaintext, aes_key, init_vec)
    return ECB.encrypt(modified_plaintext, aes_key)

def run_test() -> bool:
    #Generate random 16-bit key and initialization vector.
    chosen_plain_text = bytes("A" * 256, "ascii")
    rand_key = bytes([(randint(0,255)) for _ in range(16)])
    init_vector = bytes([(randint(0,255)) for _ in range(16)])
    #Select mode of operation randomly
    operation_mode = choice(["ECB","CBC"])
    
    #Encrypt the given plaintext through the oracle
    oracle_out = oracle_crypt(chosen_plain_text,rand_key,init_vector,operation_mode)
    
    guess = "ECB" if probablyECB(oracle_out) else "CBC"
    print("Guessed: " + guess + " ACTUAL: " + operation_mode, end="\r")
    #Check if correct
    return guess == operation_mode

#DEFINE TEST PARAMETERS
if __name__ == "__main__":
    TEST_ROUNDS = 100
    successes = 0
    for i in range(TEST_ROUNDS):
        successes += (1 if run_test() else 0)
    
    #Display results
    print("Success Rate: " + str(successes) + "/"+str(TEST_ROUNDS) + "   ")
