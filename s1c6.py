#Break repeating-key XOR

#CONSTANTS AND IMPORTS
from base64 import b64decode
from s1c3 import guess_single_byte_xor_key
from s1c5 import decrypt
KEY_SIZE_LIMIT = 100

#Simple summation method. should work for texts of the same length 

def ham_dist_byte(a: int, b: int) -> int:
    '''XORs two bytes and counts the 1s in the resulting binary operation'''
    n = a ^ b
    output = 0
    for i in range(8):
        output += n & 0x1
        n = n >> 1
    return output

#CHANGED 20APR2023: made this function a 1-liner because 1-liners are cool.
#   It has the added benefit of using the Python built-ins written in C, which
#   probably has a tiny, insignificant speedup.
def hamming_distance(buf_a: bytes, buf_b: bytes) -> int:
    '''Computes the total hamming distance for two byte-buffers. Any length mismatch is automatically counted as 8 bits of distance'''
    return sum(map(lambda a, b : ham_dist_byte(a,b), iter(buf_a), iter(buf_b))) + 8 * abs(len(buf_a) - len(buf_b))

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
the key length was 5, all because of the suggested scoring method.
'''
def score_key_length(data: bytes, length: int) -> int:
    avg_hamming_score = 0
    for i in range(len(data) // length):
        for j in range(i + 1, len(data) // length):
            avg_hamming_score += hamming_distance(data[length * i: length * (i + 1)], data[length * j: length * (j + 1)])
    return 2 * avg_hamming_score / ((len(data) // length) * ((len(data) // length) - 1) * length)

'''
This function also eliminates the biases a bit, sacrificing the truly pedantic 
nature of score_key_length(data, length) for an O(n) speedup.

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
    return min(range(min(len(data)//2, KEY_SIZE_LIMIT), 2, -1), key=lambda x : score_key_length_wrap(data,x))

#Striping mechanism
#Used to isolate characters encrypted with the same index of the key.
def stripe(data: bytes, num_blocks: int) -> list[bytes]:
    return [bytes(data[i::num_blocks]) for i in range(num_blocks)]

#Key-guessing function
def guess_key(data: bytes, length: int) -> bytes:
    blocks = stripe(data, length)
    return bytes([guess_single_byte_xor_key(block) for block in blocks])

#All-in-one Cracking Function
def crack(data: bytes) -> str:
    print("Guessing Key Length...")
    key_length_guess = guess_key_length(data)
    print(f"\nKey Length: {str(key_length_guess)}")
    print("\nGuessing Key...")
    key_guess = guess_key(data, key_length_guess)
    print(f"Key: {key_guess.decode()}")
    print("\nDecrypting...")
    return decrypt(data, key_guess).decode('ascii')
    
#Retrieve data from the challenge file.
if __name__ == "__main__":
    with open("challenge-data/6.txt", "r") as f:
        ciphertext = b64decode("".join([l.strip() for l in f.readlines()]))
        print(crack(ciphertext))
        print('--- CHALLENGE STATUS: COMPLETE ---')
