#Break "random access read/write" AES CTR

#Imports
from random import randint
from s3c18 import encrypt_AES_CTR
from s1c7 import retrieve_data, decrypt_AES_ECB_128

#Ciphertext Generator
def generate_challenge():
    nonce = randint(0, 2**64 - 1)
    key = bytes([randint(0,255) for i in range(16)])
    challenge_text = encrypt_AES_CTR(decrypt_AES_ECB_128(retrieve_data("7.txt"), bytes("YELLOW SUBMARINE","ascii")), key, nonce)

    return (challenge_text, (lambda x: encrypt_AES_CTR(x, key, nonce)))

def edit_plain(base, edit, offset):
    return bytes([(edit[i - offset] if i in range(offset, offset + len(edit)) else base[i])for i in range(len(base))])

def generate_oracle(crypt):
    return (lambda a, b, c : crypt(edit_plain(crypt(a), b, c)))

#Challenge Attack Function
def attack(ciphertext, oracle):
    return oracle(ciphertext, ciphertext, 0)

#Challenge Code
if __name__ == "__main__":
    #Generate Challenge
    chall_ct, chall_crypt = generate_challenge()

    #Generate oracle
    chall_oracle = generate_oracle(chall_crypt)

    #Attack
    chall_flag = attack(chall_ct, chall_oracle).decode("ascii")
    print(chall_flag)
    #Challenge status
    print("--- CHALLENGE STATUS: COMPLETE ---")
