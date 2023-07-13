#Scoring Dictionary, inserted manually for legibility
scores = {'e': 120, 't': 90, 'a': 80, 'i': 80, 'n': 80, 'o': 80, 's': 80, 'h': 64, 'r': 62, 'd': 44, 'l': 40, 'u': 34, 'c': 30, 'm': 30, 'f': 25, 'w': 20, 'y': 20, 'g': 17, 'p': 17, 'b': 16, 'v': 12, 'k': 8, 'q': 5, 'j': 4, 'x': 4, 'z': 2}

#Added this to prefer lowercase over uppercase.
alphabet = list(scores.keys())
for k in alphabet:
    scores[k.capitalize()] = scores[k] - 1

ignorable_chars = "1234567890!@#$%^&*(),.<>/?;:'\"[]\{\}\\|\n\t`~ "

#CHANGED 20APR2023: changed into a filter statement rather than a list comprehension.
def sanitize_buffer(buf : bytes) -> bytes:
    '''Sanitizes buffers to be "printable"/acceptable characters'''
    is_printable_ascii_byte = lambda x : (chr(x).lower() in scores.keys() or chr(x) in ignorable_chars)
    return bytes(filter(is_printable_ascii_byte, buf)) #Not sure a filter here is cleaner/more Pythonic, but whatever it's cool to use it for once :)

#CHANGED 20APR2023: used a map() function instead of iterating.
#   Added the score_byte function as a lambda to leverage Python built-ins.
def sum_score(buf : bytes) -> bytes:
    '''Computes a frequency-based score of a given buffer as a string'''
    score_byte = (lambda num : (scores[chr(num)] if chr(num) in scores.keys() else (1 if chr(num) in ignorable_chars else 0)))
    return sum(map(score_byte, sanitize_buffer(buf)))

def score_english_buffer(buf : bytes) -> int:
    '''Length-normalized scoring of a candidate plaintext buffered.'''
    return sum_score(buf)/len(buf)

def decrypt_single_byte_xor(buf : bytes, kb : int) -> bytes:
    '''Given a buffer buf and byte kb, returns the result of xoring each byte of buf with kb'''
    return bytes([x ^ kb for x in buf])

def safe_decode_string_from_bytes(buf : bytes) -> str:
    '''Safely decodes and sanitizes a buffer from'''
    return "".join([chr(c) for c in sanitize_buffer(buf)])

def guess_single_byte_xor_key(buf : bytes) -> int:
    '''Returns the most likely key for a ciphertext buffer based on frequency analysis'''
    return max(range(256), key= lambda x : score_english_buffer(decrypt_single_byte_xor(buf, x)))

def rank_keybytes(buf : bytes):
    '''Returns the 256 possible keys, ranked in order of increasing plaintext score for a given buffer'''
    return sorted(range(256), key=lambda x : score_english_buffer(decrypt_single_byte_xor(buf, x)))
    

#Challenge code
if __name__ == "__main__":
    ciphertext = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    for k in rank_keybytes(ciphertext):
        plaintext = decrypt_single_byte_xor(ciphertext, k)
        print(f"{(safe_decode_string_from_bytes(plaintext))} | SCORE {score_english_buffer(plaintext)}") 
    print("--- CHALLENGE STATUS: COMPLETE ---")
'''Cooking MC's like a pound of bacon'''