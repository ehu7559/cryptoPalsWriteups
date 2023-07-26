#Challenge 20

#Imports
from s1c6 import guess_key, decrypt
from base64 import b64decode
from s3c19 import gen_crypt_oracle, defang_str_bytes

#Attack function
def challenge_20_attack(ciphertexts: list) -> int:
    #Get shortest string length
    shortest = len(min(ciphertexts, key=len))
    #Concatenate them
    attack_text = bytearray()
    for c in ciphertexts:
        attack_text.extend(c[0:shortest])
    #Solve for key and return it
    return guess_key(bytes(attack_text), shortest)

#Challenge Code
if __name__ == "__main__":
    
    with open("challenge-data/19.txt", "r") as f:
        #Retrieve data and process it
        plain_texts = [bytes(b64decode(l)) for l in f.readlines()]

        #Generate encryption oracle and encrypt the ciphertexts
        chall_oracle = gen_crypt_oracle()
        cipher_texts = [chall_oracle(p) for p in plain_texts]

        key_guess = challenge_20_attack(cipher_texts)

        recovered = [decrypt(c, key_guess) for c in cipher_texts]
        
        for (a, b) in zip(plain_texts, recovered):
            print(a.decode())
            print(defang_str_bytes(b))

        #Compile guesses
        print("--- CHALLENGE STATUS: COMPLETE ---")