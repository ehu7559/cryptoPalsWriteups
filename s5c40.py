#Challenge 40: Implement an E=3 RSA Broadcast attack

#Imports
from s5c39 import mod_inv as invmod
from s5c33 import unbounded_exp as exp #Used for int_root function

def int_root(n : int, r : int, strict=False) -> int:
    '''Computes rth root of n. Does not handle complex/Gaussian integers
    It's not that I don't like the built-ins. It's that casting from floating point to integer is not accurate enough.'''
    #Can't handle non-natural roots.
    if r < 1:
        raise Exception("Invalid value for root power")
    #Quick catch case for speed.
    if n == 0:
        return 0
    #Handling negatives
    if n < 0:
        if r % 2 == 0:
            raise Exception("Imaginary Number")
        return -1 * int_root(abs(n), r)
    
    #Find bounding power of 2
    curr = 1
    while exp(curr, r) <= n:
        curr = curr << 1 
    
    #Compute using binary search
    acc = 0
    while curr:
        acc = acc if exp((acc + curr), r) > n else (acc + curr)
        curr = curr >> 1 #Decrement the curr
    
    #Check for validity
    if exp(acc, r) == n:
        return acc
    
    if strict:
        raise Exception(f"The root {r} of {n} is not an integer.")
    return acc

#Haha funny lambda function definition
#probably could have done this from the beginning but generalized solutions are cool.
#Also, it means I can use it in other problems later :3.
cube_root = lambda x : int_root(x, 3)

def rsa_e3_broadcast_attack(ciphertexts, moduli):
    '''Recovers a plaintext given the ciphertext resulting from encryption with three distinct RSA public keys.'''
    if len(ciphertexts) != 3:
        raise Exception(f"Expected 3 ciphertexts. Found {len(ciphertexts)}.")
    if len(moduli) != 3:
        raise Exception(f"Expected 3 moduli. Found {len(moduli)}.")
    c_0, c_1, c_2 = ciphertexts
    n_0, n_1, n_2 = moduli
    m_s_0, m_s_1, m_s_2 = n_1 * n_2, n_0 * n_2, n_0 * n_1
    result = ((c_0 * m_s_0 * invmod(m_s_0, n_0)) + (c_1 * m_s_1 * invmod(m_s_1, n_1)) + (c_2 * m_s_2 * invmod(m_s_2, n_2))) % (n_0 * n_1 * n_2) 
    return cube_root(result)

if __name__ == "__main__":
    pass