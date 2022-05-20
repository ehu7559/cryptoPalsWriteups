from s1c3 import decrypt


FREQS = {'e': 120, 't': 90, 'a': 80, 'i': 80, 'n': 80, 'o': 80, 's': 80, 'h': 64, 'r': 62, 'd': 44, 'l': 40, 'u': 34, 'c': 30, 'm': 30, 'f': 25, 'w': 20, 'y': 20, 'g': 17, 'p': 17, 'b': 16, 'v': 12, 'k': 8, 'q': 5, 'j': 4, 'x': 4, 'z': 2}
MIN_SCORE = 1200

#Simple summation method. should work for texts of the same length 
def score_text(data):
    points = 0
    for i in data:
        if i in range(128) and chr(i) in FREQS.keys():
            points += FREQS[chr(i)]
    return points

def crack_byte(data):
    for i in range(128):
        ptxt = decrypt(bytes.fromhex(data),i)
        sc = score_text(ptxt)
        if sc > MIN_SCORE:
            print(ptxt.decode('ascii').strip())

#Challenge Data
def retrieve_data():
    with open('4.txt',"r") as f:
        return f.readlines()

if __name__ == "__main__":
    for l in retrieve_data():
        crack_byte(l)
    print("--- CHALLENGE STATUS: COMPLETE ---")
