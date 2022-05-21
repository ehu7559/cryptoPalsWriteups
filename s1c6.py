#CONSTANTS AND IMPORTS
from base64 import b64decode
KEY_SIZE_LIMIT = 100
FREQS = {'e': 120, 't': 90, 'a': 80, 'i': 80, 'n': 80, 'o': 80, 's': 80, 'h': 64, 'r': 62, 'd': 44, 'l': 40, 'u': 34, 'c': 30, 'm': 30, 'f': 25, 'w': 20, 'y': 20, 'g': 17, 'p': 17, 'b': 16, 'v': 12, 'k': 8, 'q': 5, 'j': 4, 'x': 4, 'z': 2}

#Simple summation method. should work for texts of the same length 
def score_text(data):
    points = 0
    for i in data:
        if i in range(128) and chr(i) in FREQS.keys():
            points += FREQS[chr(i)]
    return points

def ham_dist_byte(a, b):
    n1 = a
    n2 = b
    output = 0
    for i in [128, 64, 32, 16, 8, 4, 2, 1]:
        output += 0 if (n1 >= i) == (n2 >= i) else 1
        n1 = n1 % i
        n2 = n2 % i
    return output

def hamming_distance(buf_a, buf_b):
    output = 0
    for i in range(min(len(buf_a), len(buf_b))):
        output += ham_dist_byte(buf_a[i], buf_b[i])
    output += 8 * abs(len(buf_a) - len(buf_b))
    return output

'''
This function is incredibly slow, but yields a far higher confidence in the
resulting kasiski analysis. The suggested method of using a single block size to
check this is broken as fuck, especially given shorter key sizes' susceptibility
to the biases found in the beginning of the text.

In the original implementation, this would consistently return a key length of 5
characters, which was patently incorrect given that the actual key length was 29
characters, leading to an entirely illegible ciphertext that took multiple days
to resolve (as 5 and 29 are coprime). This problem led to much filtering on
printable characters. What a pain this problem was, all thanks to this goddamn
function!
'''
def score_key_length(data, length):
    avg_hamming_score = 0
    for i in range(len(data) // length):
        for j in range(i + 1, len(data) // length):
            avg_hamming_score += hamming_distance(data[length * i: length * (i + 1)], data[length * j: length * (j + 1)])
    return 2 * avg_hamming_score / ((len(data) // length) * ((len(data) // length) - 1) * length)

'''
This one would also have eliminated the biases a little bit, sacrificing the
truly pedantic nature of score_key_length(data, length). This is the algorithm
I used for Kasiski analysis during CMSC414 at the University of Maryland.

Thanks to Dr. Marsh and Dr. Manning for teaching me this.
'''
def score_key_length_wrap(data, length):
    return sum([ham_dist_byte(data[i], data[(i + length) % len(data)]) for i in range(len(data))])/ (len(data) * 1.0)
    
#Looping mechanism for guessing key length
def guess_key_length(data):
    '''(bytes) -> int'''
    if len(data) < 2:
        return len(data)    
    guess = 1
    guess_score = 8     #Literally every bit is different
    for i in range(1,(min(len(data)//2, KEY_SIZE_LIMIT))):
        sc = score_key_length_wrap(data,i)
        if sc < guess_score: #Prefer shorter key size (I think it would make for more reliable frequency analysis)
            print("Length: "+str(i) + " \tScore: "+ str(sc))
            guess = i
            guess_score = sc    
    return guess

#Striping mechanism 
def stripe(data, num_blocks):
    output = []
    
    #Initialize
    for i in range(num_blocks):
        output.append(bytearray())
    
    #Stripe out data
    for i in range(len(data)):
        output[i%num_blocks].append(data[i])
    
    return output

def can_be_ascii(buffer):
    for a in buffer:
        if a not in range(127):
            return False
    return True

def safe_byte_crack(ciphertext):
    best_i = 0
    max_score = 0
    for i in range(256):

        #Generate the resulting plaintext
        maybe_plain = bytes([a ^ i for a in ciphertext])
        
        #Filter out the unprintables as null-candidates
        if not can_be_ascii(maybe_plain):
            continue
        
        new_score = score_text(maybe_plain)
        
        if new_score >= max_score:
            best_i = i
            max_score = new_score

    return best_i

#Key-guessing function
def guess_key(data, length):
    blocks = stripe(data, length)
    kb = bytearray()
    for bl in blocks:
        kb.append(safe_byte_crack(bl))
    return bytes(kb)

def decrypt(data, key):
    return bytes([int((data[i]) ^ (key[i % len(key)])) for i in range(len(data))])

def crack(data):
    print("Guessing Key Length...")
    key_length_guess = guess_key_length(data)
    print("Key Length: " + str(key_length_guess))
    print("\nGuessing Key:")
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
    print('--- CHALLENGE STATUS: COMPLETE ---')