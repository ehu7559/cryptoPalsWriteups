
#Challenge 20

#Imports
from s1c6 import guess_key
from s3c19 import get_crypt_oracle, retrieve_lines


#Attack function
def challenge_20_attack(ciphertexts):
    pass

#Challenge Code
if __name__ == "__main__":
    
    #Generate encryption oracle and challenge texts
    cryptoracle = get_crypt_oracle()
    cipher_texts = retrieve_lines("19.txt")
    
    #Attack
    chall_key_guess = guess_key(cipher_texts)

    #Decode and encrypt each text
    for c in cipher_texts:
        pass
    print("--- CHALLENGE STATUS: COMPLETE ---")