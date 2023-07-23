#Challenge 20

#Imports
from s1c6 import guess_key, decrypt
from s3c19 import get_crypt_oracle, retrieve_lines, safe_print

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
    
    #Generate encryption oracle and challenge texts
    cryptoracle = get_crypt_oracle()
    plain_texts = retrieve_lines("challenge-data/20.txt")
    cipher_texts = [cryptoracle(p) for p in plain_texts]
    
    #Attack
    chall_key_guess = challenge_20_attack(cipher_texts)

    #Decode and encrypt each text
    for c in cipher_texts:
        safe_print(decrypt(c,chall_key_guess))
    
    print("--- CHALLENGE STATUS: COMPLETE ---")