#Create the MT19937 stream cipher and break it
from s3c21 import MT19937_stream
from random import randint

def MT19937_bytestream(seed):
    generator = MT19937_stream(seed)
    byte_stack = bytearray()
    while True:
        x = next(generator)
        byte_stack.append(x & 0xFF)
        x = x >> 8
        byte_stack.append(x & 0xFF)
        x = x >> 8
        byte_stack.append(x & 0xFF)
        x = x >> 8
        byte_stack.append(x & 0xFF)
        yield byte_stack.pop()
        yield byte_stack.pop()
        yield byte_stack.pop()
        yield byte_stack.pop()

def MT19937_cipher(seed, data):
    keystream = MT19937_bytestream(seed)
    return bytes([x ^ next(keystream) for x in data])

def get_cipher_oracle(seed):
    return lambda x : MT19937_cipher(seed, x)


def MT19937_cipher_KPA(oracle):
    ciphertext = oracle(bytes(2496))
    for i in range(2**16):
        print(f"TRYING SEED: {i}", end="\r")
        brute_gen = MT19937_bytestream(i)
        match = True
        for j in range(2496):
            if next(brute_gen) != ciphertext[j]:
                match = False
                break
        if match:
            return i
    return -1

#Run Challenge.
if __name__ == "__main__":
    #Generate 16-bit seed and encryption oracle
    chall_seed = randint(0, 2**16 - 1)
    print(f"Challenge Seed: {chall_seed}")
    chall_oracle = get_cipher_oracle(chall_seed)

    #Generate known plaintext
    cracked_seed = MT19937_cipher_KPA(chall_oracle)

    #Print results.
    print(f"\nCracked Seed: {cracked_seed}")
