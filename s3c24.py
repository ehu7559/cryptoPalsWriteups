#Create the MT19937 stream cipher and break it
from s3c21 import MT19937_stream
from random import randint

def MT19937_bytestream(seed):
    generator = MT19937_stream(seed)
    byte_stack = bytearray()
    while True:
        x = next(generator)
        byte_stack.append(x%256)
        x = x // 256
        byte_stack.append(x%256)
        x = x // 256
        byte_stack.append(x%256)
        x = x // 256
        byte_stack.append(x%256)
        yield byte_stack.pop()
        yield byte_stack.pop()
        yield byte_stack.pop()
        yield byte_stack.pop()

def MT19937_cipher(seed, data):
    keystream = MT19937_bytestream(seed)
    return bytes([x ^ next(keystream) for x in data])

def get_cipher_oracle(seed):
    return lambda x : MT19937_cipher(seed, x)

def MT19937_cipher_KPA(plaintext, oracle):
    ciphertext = oracle(plaintext)
    for i in range(2**16):
        print(f"TRYING SEED: {i}", end="\r")
        brute_text = MT19937_cipher(i, plaintext)
        match = True
        for j in range(len(ciphertext)):
            if (brute_text[j] != ciphertext[j]):
                match = False
        if match:
            return i
    return -1

if __name__ == "__main__":
    #Generate 16-bit seed and encryption oracle
    chall_seed = randint(0, 2**16 - 1)
    chall_oracle = get_cipher_oracle(chall_seed)

    #Generate known plaintext
    chall_plaintext = bytes(randint(0, 255) for i in range(2496))
    cracked_seed = MT19937_cipher_KPA(chall_plaintext, chall_oracle)

    #Print results.
    print(f"Challenge Seed: {chall_seed}\nCracked Seed: {cracked_seed}")