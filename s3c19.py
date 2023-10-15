#IMPORTS
from base64 import b64decode
from s1c2 import xor
from s1c3 import guess_single_byte_xor_key, defang_str_bytes
from random import randint
from s3c18 import AES_CTR as CTR

def gen_crypt_oracle():
    key = bytes([randint(0, 255) for _ in range(16)])
    nonce = randint(0, 0xffffffffffffffff)
    return lambda x : (CTR.encrypt(x, key, nonce))

def split_ciphertexts(ciphertexts: list[bytes]) -> list[bytes]:
    max_len = max([len(c) for c in ciphertexts])
    output = []
    for x in range(max_len):
        buf = bytearray()
        for c in ciphertexts:
            if x < len(c):
                buf.append(c[x])
        output.append(bytes(buf))
    return output

def gen_pad_guess(ciphertexts: list[bytes]):
    return bytes([guess_single_byte_xor_key(buf) for buf in split_ciphertexts(ciphertexts)])

#Challenge Code
if __name__ == "__main__":
    with open("challenge-data/19.txt", "r") as f:
        #Retrieve data and process it
        plain_texts = [bytes(b64decode(l)) for l in f.readlines()]

        #Generate encryption oracle
        chall_oracle = gen_crypt_oracle()

        #Encrypt the ciphertexts:
        cipher_texts = [chall_oracle(p) for p in plain_texts]

        #
        recovery_pad = gen_pad_guess(cipher_texts)
        recovered = [xor(c, recovery_pad[0:len(c)]) for c in cipher_texts]

        for (a, b) in zip(plain_texts, recovered):
            print(a.decode())
            print(defang_str_bytes(b))
        #Compile guesses
        print("--- CHALLENGE STATUS: COMPLETE ---")