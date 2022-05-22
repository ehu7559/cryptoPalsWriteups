#helper-method to ensure alphabetical characters only
forbiddenchars = ""

#Scoring Dictionary, inserted manually for legibility
scores = {'e': 120, 't': 90, 'a': 80, 'i': 80, 'n': 80, 'o': 80, 's': 80, 'h': 64, 'r': 62, 'd': 44, 'l': 40, 'u': 34, 'c': 30, 'm': 30, 'f': 25, 'w': 20, 'y': 20, 'g': 17, 'p': 17, 'b': 16, 'v': 12, 'k': 8, 'q': 5, 'j': 4, 'x': 4, 'z': 2}

#Simple summation method. should work for texts of the same length 
def sanitize(txt):
    output = ""
    for c in txt.lower():
        if c in scores.keys():
            output += c
    return output

def sum_score(txt):
    points = 0
    for i in sanitize(txt):
        points += scores[i]
    return points

def printable(raw_text):
    for i in bytes(raw_text):
        if (i < 32 or i > 127) or chr(i) in forbiddenchars:
            return False
    return True

def ranked_plaintexts(raws):
    #score printable outputs
    scorechart = {}
    for traw in raws:
        if printable(traw):
            t = traw.decode('utf8')
            scorechart[t] = sum_score(t)
    
    #Selection-sort them into an output array
    output = []
    while len(scorechart.keys())>0:
        max_t = ""
        max_score = 0
        for t in scorechart.keys():
            if scorechart[t] > max_score:
                max_t = t
                max_score = scorechart[t]
        output.append(max_t)
        scorechart.pop(max_t)
    
    return output

def decrypt(cipherbytes, keybyte):
    return bytes([(bite ^ keybyte) for bite in cipherbytes])

#This is left here just for completeness' sake. it's just an alias.
def encrypt(plainbytes, keybyte):
    return decrypt(plainbytes, keybyte)

#Function for actually cracking a given ciphertext
def crackbyte(hex_string):
    
    cipher_raw = bytes.fromhex(hex_string)

    #Generate plain-text space
    plainspace = []
    for i in range(256):
        plainspace.append(decrypt(cipher_raw, i))
    #Score and rank texts
    candidates = ranked_plaintexts(plainspace)

    #Print all candidates
    for c in candidates:
        print(c + " \t" + str(sum_score(c)))

#Challenge code
if __name__ == "__main__":
    crackbyte("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    print("--- CHALLENGE STATUS: COMPLETE ---")
'''Cooking MC's like a pound of bacon'''