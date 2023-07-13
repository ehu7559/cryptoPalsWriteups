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

    w = (s - 1) % q
    H = int(SHA1.hash(m), 16)
    u_1 = ((H % q) * (w % q)) % q
    u_2 = ((r % q) * (w % q)) % q
    v = (pow(gmm))
    
#Challenge Code
if __name__ == "__main__":
    pass