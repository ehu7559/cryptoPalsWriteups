#Challenge 44: DSA nonce recovery from repeated nonce
from s4c28 import SHA1
from s5c39 import gcd, mod_inv
from s6c43 import priv_key_from_known_k_with_hash

def get_shared_k(params, sig1, sig2):
    '''
    ((int, int, int), (str, int, int, SHA1_str), (str, int, int, SHA1_str)) -> int
    Given DSA params and two distinct signatures with message and hash signed 
    with the same value of k (see DSA algorithm), computes the shared k.
    Returns None if a solution cannot be found.
    params are (p, q, g) as per DSA specifications (see Wikipedia)
    signatures are (message string, s, r, SHA-1 hash) as per the challenge's
    specifications.
    '''
    
    #Unpack params
    _, q, _ = params
    _, s1, _, h1 = sig1
    _, s2, _, h2 = sig2
    #Convert hashes to integers for some fancy math uwu
    h1 = int(h1, base=16)
    h2 = int(h2, base=16)
    s = (s1 - s2) % q
    h = (h1 - h2) % q
    #Catch case to prevent uninvertibles/div by 0.
    if s == 0 or gcd(s, q) > 1: return None
    #Invert s
    s_inv = mod_inv(s,q)
    #Compute shared k and return
    return (h * s_inv) % q

if __name__ == "__main__":
    
    #Challenge constants
    chall_pubkey= 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821
    chall_p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    chall_q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    chall_g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
    chall_params = (chall_p, chall_q, chall_g)
    chall_sol_ref_hash = "ca8f6f7c66fa362d40760d135b763eb8527d3d52" #SHA1 to present as proof of completion

    #parse the logfile.
    chall_text_lines = []
    with open("challenge-data/44.txt", "r") as f:
        chall_text_lines = f.readlines()
    chall_signatures = []
    for i in range(len(chall_text_lines)//4):
        sig_msg = chall_text_lines[(4 * i)][5:-1]
        sig_s   = int(chall_text_lines[(4 * i) + 1][3:], base=10)
        sig_r   = int(chall_text_lines[(4 * i) + 2][3:], base=10)
        sig_h   = chall_text_lines[(4 * i) + 3][3:-1]
        chall_signatures.append((sig_msg, sig_s, sig_r, sig_h))
    
    #Iterate over the signatures to find the shared k.
    chall_k = None
    test_sig_pair = None
    test_hash = None
    for a in chall_signatures:
        a_msg, a_s, a_r, a_h = a
        for b in chall_signatures:
            b_msg, b_s, b_r, b_h = b
            if a_h == b_h: continue #avoids comparing against itself.
            if a_r != b_r: continue #shared k + params implies shared r.
            #Shared r and shared params imply shared k.
            chall_k = get_shared_k(chall_params, a, b)
            test_sig_pair = (a_r, a_s) #Save a signature for later
            test_hash = a_h
            break
        if chall_k is not None: break

    assert(chall_k is not None)

    #Get the shared x.
    print(f"RECOVERED K: {chall_k}")
    x = priv_key_from_known_k_with_hash(chall_params, test_hash, test_sig_pair, chall_k)
    print(f"PRIV KEY: {x}")
    priv_key_hash = SHA1.hash((hex(x)[2:]).encode())
    print(f"PRIV KEY HASH: {priv_key_hash}")
    print(f"SOLUTION HASH: {chall_sol_ref_hash}")
    chall_successful = priv_key_hash == chall_sol_ref_hash
    print(f"--- CHALLENGE STATUS: {'COMPLETE' if chall_successful else 'FAILURE'} ---")