#Challenge 43

#Imports
from s4c28 import SHA1 #SHA-1 is the default hash function
from random import randint

class DSA:

    def gen_params(p, q, g=None):
        assert(p > q)
        assert((p - 1) % q == 0)
        if g is None:
            g = pow(2, (p-1)//q, p)
            while g == 1:
                h = randint(2, p - 2)
                g = pow(h, (p-1)//q, p)
            return (p, q, g)
        assert(g > 1)
        g = g % p
        return (p, q, g)
    
    def gen_keypair(params):
        p, q, g = params
        x = randint(1, q - 1)
        y = pow(g, x, p)
        return (x, y)
    
    def gen_signature(params):
        pass

    def sign(params, message : bytes, k : int, keypair):
        p, q, g = params
        x, _ = keypair
        r = pow(g, k, p) % q
        k_inv = pow(k, -1, q)
        H_m = int((SHA1.hash(message)),base=16)
        s = (k_inv * (H_m + (x * r))) % q
        return (r, s)
    
    def verify_signature(params, message : bytes, signature, pub_key : int):
        p, q, g = params
        y = pub_key
        r, s = signature
        H_m = int((SHA1.hash(message)),base=16)

        w = pow(s, -1, q)
        u1 = (H_m * w) % q
        u2 = (r * w) % q
        v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q

        return v==r

def priv_key_from_known_k(params, message : bytes, signature, k):
    p, q, g = params
    r, s = signature
    r_inv = pow(r, -1, q)
    H_m = int((SHA1.hash(message)),base=16)
    return (r_inv * ((s * k) - H_m)) % q

if __name__ == "__main__":
    chall_p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    chall_q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    chall_g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
    chall_params = (chall_p, chall_q, chall_g)
    
    chall_message = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n".encode()

    assert(SHA1.hash(chall_message) == "d2d0714f014a9784047eaeccf956520045c45265")

    chall_r = 548099063082341131477253921760299949438196259240
    chall_s = 857042759984254168557880549501802188789837994940
    chall_sig = (chall_r, chall_s)

    for i in range(2**16):
        print(f"k = {i}", end="\r")
        chall_x = priv_key_from_known_k(chall_params, chall_message, chall_sig, i)
        chall_x_hex = hex(chall_x)[2:]
        fingerprint = SHA1.hash(chall_x_hex.encode())
        if fingerprint == "0954edd5e0afe5542a4adf012611a91912a3ec16":
            print(f"k = {i}, x = {chall_x}")  