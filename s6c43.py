#Challenge 43

#Imports
from s4c28 import SHA1 #SHA-1 is the default hash function
from random import randint

#Parameter generation

#Key Generation
def gen_key(shared_params):
    p, q, g = shared_params
    assert(q > 1)
    x = randint(1, q - 1)
    y = pow(g, x, p)
    return (x, y) #x is private key, y is public key

#Signature Code
def sign_message(m : bytes, shared_params, priv_key):
    p, q, g = shared_params
    r, s = 0
    H = int(SHA1.hash(m), 16)
    while not (r and s):
        k = randint(1, q - 1)
        r = pow(g, k, p) % q
        s = (pow(k, -1, q) * (H + (priv_key * r))) % q
    return (r, s)

#Signature Verification Code
def verify_signature(m : bytes, signature : tuple[int], shared_params, pub_key):
    r, s = signature
    p, q, g = shared_params
    y = pub_key

    w = pow(s, -1, q) #I've previously implemented inv_mod. Using pow here for speed.
    H = int(SHA1.hash(m), 16)
    u_1 = ((H % q) * (w % q)) % q
    u_2 = ((r % q) * (w % q)) % q
    v = ((pow(g, u_1, p) * pow(y, u_2, p)) % p) % q
    return v == r

def retrieve_private_key_from_known_k(shared_params, m, signature, k):
    r, s = signature
    p, q, g = shared_params
    H = int(SHA1.hash(m), 16)
    return ((s * k - H) * pow(r, -1, q)) % q

#Challenge Code
if __name__ == "__main__":
    #Initial parameters
    chall_p = int("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16) 
    chall_q = int("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
    chall_g = int("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16)

    #Signed Message
    chall_m = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch".encode(encoding="utf-8")

    #Check that the string is correct
    print(SHA1.hash(chall_m))
    #I checked the SHA-1 hash for the message online. It seems they've put the wrong hash in the challenge text.
    #Doesn't seem to hash to d2d0714f014a9784047eaeccf956520045c45265