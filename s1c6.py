#CONSTANTS AND IMPORTS
from base64 import b64decode
from s1c3 import score_english_buffer, guess_single_byte_xor_key
from s1c5 import decrypt
KEY_SIZE_LIMIT = 100

#Simple summation method. should work for texts of the same length 

def ham_dist_byte(a: int, b: int) -> int:
    '''XORs two bytes and counts the 1s in the resulting binary operation'''
    n = a ^ b
    output = 0
    for i in range(8):
        output += n % 2
        n = n >> 1
    return output

def hamming_distance(buf_a: bytes, buf_b: bytes) -> int:
    output = 0
    for i in range(min(len(buf_a), len(buf_b))):
        output += ham_dist_byte(buf_a[i], buf_b[i])
    output += 8 * abs(len(buf_a) - len(buf_b))
    return output

'''
This function is incredibly slow, but yields a far higher confidence in the
resulting Kasiski analysis. The suggested method of using a single block size to
check this is extremely broken, especially given shorter key sizes' 
susceptibility to the biases found in the beginning of the text. This function
is quadratic in time with respect to the length of the data, which is horrible.

In the original implementation, this would consistently return a key length of 5
characters, which was patently incorrect given that the actual key length was 29
characters, leading to an entirely illegible ciphertext that took multiple days
to resolve (as 5 and 29 are coprime). This problem led to much filtering on
printable characters and other attempts to obtain the plaintext assuming that
the key length was 5, all becuase of the suggested function.
'''
def score_key_length(data: bytes, length: int) -> int:
    avg_hamming_score = 0
    for i in range(len(data) // length):
        for j in range(i + 1, len(data) // length):
            avg_hamming_score += hamming_distance(data[length * i: length * (i + 1)], data[length * j: length * (j + 1)])
    return 2 * avg_hamming_score / ((len(data) // length) * ((len(data) // length) - 1) * length)

'''
This one would also have eliminated the biases a bit, sacrificing the truly 
pedantic nature of score_key_length(data, length) for an O(n) speedup.
This is the algorithm I used for Kasiski analysis during CMSC414 and CMSC456 at
the University of Maryland.

Thanks to Dr. Marsh and Dr. Manning for teaching me this.

(Addendum: I may or may not be a little proud that this is a one-liner :3 )
'''
def score_key_length_wrap(data: bytes, length: int) -> int:
    return sum([ham_dist_byte(data[i], data[(i + length) % len(data)]) for i in range(len(data))])/ (len(data) * 1.0)
    
#Looping mechanism for guessing key length
def guess_key_length(data: bytes) -> int:
    '''(bytes) -> int
        Returns the most likely key length in bytes given a ciphertext encrypted
        with repeated-key XOR'''
    if len(data) < 2:
        return len(data)    
    guess = 1
    guess_score = 8     #Literally every bit is different
    for i in range(1,(min(len(data) // 2, KEY_SIZE_LIMIT))):
        sc = score_key_length_wrap(data,i)
        if sc < guess_score: #Prefer shorter key size (I think it would make for more reliable frequency analysis)
            print(f"Current Candidate: {guess} \tChecking: {i}", end="\r")
            guess = i
            guess_score = sc    
    return guess
    
#Striping mechanism
#Used to isolate characters encrypted with the same index of the key.
def stripe(data: bytes, num_blocks: int) -> list[bytes]:
    output = []
    
    #Initialize
    for i in range(num_blocks):
        output.append(bytearray())
    
    #Stripe out data
    for i in range(len(data)):
        output[i%num_blocks].append(data[i])
    
    return output

def can_be_ascii(buffer: bytes) -> bool:
    for a in buffer:
        if a not in range(127):
            return False
    return True

#Key-guessing function
def guess_key(data: bytes, length: int) -> bytes:
    blocks = stripe(data, length)
    kb = bytearray()
    for bl in blocks:
        kb.append(guess_single_byte_xor_key(bl))
    return bytes(kb)

#Decryption function
def decrypt(data: bytes, key: bytes) -> bytes:
    return bytes([int((data[i]) ^ (key[i % len(key)])) for i in range(len(data))])

#All-in-one Cracking Function
def crack(data: bytes) -> str:
    print("Guessing Key Length...")
    key_length_guess = guess_key_length(data)
    print("\nKey Length: " + str(key_length_guess))
    print("\nGuessing Key...")
    key_guess = guess_key(data, key_length_guess)
    print("Key: " + str(key_guess))
    print("\nDecrypting...")
    return decrypt(data, key_guess).decode('ascii')

def retrieve_data(filename):
    '''(string) -> bytes'''
    f = open(filename, "r")
    ls = f.readlines()
    f.close()
    sixtyfour = ""
    for l in ls:
        sixtyfour += l.strip()
    return bytes(b64decode(sixtyfour))
    
#Retrieve data from the challenge file.
if __name__ == "__main__":    
    ciphertext = retrieve_data("6.txt")
    print(crack(ciphertext))
    #The proper key is this
    print(decrypt(ciphertext, "Terminator X: Bring the noise".encode("ascii")).decode("ascii"))
    print('--- CHALLENGE STATUS: COMPLETE ---')
