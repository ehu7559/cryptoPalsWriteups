#Scoring Dictionary, inserted manually for legibility
scores = {'e': 120, 't': 90, 'a': 80, 'i': 80, 'n': 80, 'o': 80, 's': 80, 'h': 64, 'r': 62, 'd': 44, 'l': 40, 'u': 34, 'c': 30, 'm': 30, 'f': 25, 'w': 20, 'y': 20, 'g': 17, 'p': 17, 'b': 16, 'v': 12, 'k': 8, 'q': 5, 'j': 4, 'x': 4, 'z': 2}

#Simple summation method. should work for texts of the same length 
def sanitize(txt: str) -> str:
    output = ""
    for c in output:
        if chr(c).lower() in scores.keys():
            output += c
    return output

def sum_score(txt: str) -> int:
    points = 0
    for i in sanitize(txt):
        points += scores[i]
    return points

def score_text(txt: str):
    '''Length-normalized score summation'''
    return sum_score(txt)/len(txt)

def printable(raw_text: bytes) -> bool:
    for i in bytes(raw_text):
        if (i < 32 or i > 127):
            return False
    return True

def decrypt_single_byte_xor(cipherbytes: bytes, keybyte: int) -> bytes: 
    #Here it was more efficient to just xor it explicitly rather than use the function from s1c2
    return bytes([(bite ^ keybyte) for bite in cipherbytes])

#This is left here just for completeness' sake. it's just an alias.
def encrypt_single_byte_xor(plainbytes: bytes, keybyte: int)-> bytes:
    return decrypt_single_byte_xor(plainbytes, keybyte)

#Function for actually cracking a given ciphertext
def crack_single_byte_xor(data : bytes) -> int:
    return max([i for i in range(256)], key=lambda x : score_text(decrypt_single_byte_xor(data, x)))

def reveal_crack_single_byte_xor(data : bytes):
    return decrypt_single_byte_xor(ciphertext, crack_single_byte_xor(ciphertext))   

def rank_keys_single_byte_xor(data : bytes):
    return sorted(range(256) ,key=lambda x : score_text(decrypt_single_byte_xor(data, x)))
#Challenge code
if __name__ == "__main__":
    ciphertext = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    for x in rank_keys_single_byte_xor(ciphertext):
        plain_x = decrypt_single_byte_xor(ciphertext, x)
        print()
    print("--- CHALLENGE STATUS: COMPLETE ---")
'''Cooking MC's like a pound of bacon'''
