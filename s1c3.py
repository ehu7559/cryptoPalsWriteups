#Scoring Dictionary, inserted manually for legibility
scores = {'e': 120, 't': 90, 'a': 80, 'i': 80, 'n': 80, 'o': 80, 's': 80, 'h': 64, 'r': 62, 'd': 44, 'l': 40, 'u': 34, 'c': 30, 'm': 30, 'f': 25, 'w': 20, 'y': 20, 'g': 17, 'p': 17, 'b': 16, 'v': 12, 'k': 8, 'q': 5, 'j': 4, 'x': 4, 'z': 2}
ignorable_chars = "1234567890!@#$%^&*(),.<>/?;:'\"[]\{\}\\|\n\t`~ "

#Simple summation method. should work for texts of the same length 
def is_printable_ascii_byte(x : int) -> bool:
    return chr(x).lower() in scores.keys() or chr(x) in ignorable_chars

def sanitize_buffer(buf : bytes) -> bytes:
    '''Sanitizes buffers to be "printable"/acceptable characters'''
    return bytes([(x) for x in buf if is_printable_ascii_byte(x)])

def sum_score(buf : bytes) -> bytes:
    '''Computes a frequency-based score of a given buffer as a string'''
    output = 0
    for i in sanitize_buffer(buf):
        output += scores[chr(i).lower()] if chr(i).lower() in scores.keys() else 0
    return output

def score_english_buffer(buf : bytes):
    return sum_score(buf)/len(buf)

def decrypt_single_byte_xor(buf : bytes, kb : int) -> bytes:
    return bytes([x ^ kb for x in buf])

def safe_decode_string_from_bytes(buf : bytes):
    return "".join([chr(c) for c in sanitize_buffer(buf)])

def guess_single_byte_xor_key(buf : bytes):
    return max(range(256), key= lambda x : score_english_buffer(decrypt_single_byte_xor(buf, x)))

def rank_keybytes(buf : bytes):
    return sorted(range(256), key=lambda x : score_english_buffer(decrypt_single_byte_xor(buf, x)))
    

#Challenge code
if __name__ == "__main__":
    ciphertext = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    for k in rank_keybytes(ciphertext):
        plaintext = decrypt_single_byte_xor(ciphertext, k)
        print(safe_decode_string_from_bytes(plaintext)) 
    print("--- CHALLENGE STATUS: COMPLETE ---")
'''Cooking MC's like a pound of bacon'''
