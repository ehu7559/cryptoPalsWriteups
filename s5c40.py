'''
Implement an E=3 RSA Broadcast attack
Assume you're a Javascript programmer. That is, you're using a naive handrolled RSA to encrypt without padding.

Assume you can be coerced into encrypting the same plaintext three times, under three different public keys. You can; it's happened.

Then an attacker can trivially decrypt your message, by:

Capturing any 3 of the ciphertexts and their corresponding pubkeys
Using the CRT to solve for the number represented by the three ciphertexts (which are residues mod their respective pubkeys)
Taking the cube root of the resulting number
The CRT says you can take any number and represent it as the combination of a series of residues mod a series of moduli. In the three-residue case, you have:

result =
(c_0 * m_s_0 * invmod(m_s_0, n_0)) +
(c_1 * m_s_1 * invmod(m_s_1, n_1)) +
(c_2 * m_s_2 * invmod(m_s_2, n_2)) mod N_012
where:

c_0, c_1, c_2 are the three respective residues mod
n_0, n_1, n_2

m_s_n (for n in 0, 1, 2) are the product of the moduli
EXCEPT n_n --- ie, m_s_1 is n_0 * n_2

N_012 is the product of all three moduli
To decrypt RSA using a simple cube root, leave off the final modulus operation; just take the raw accumulated result and cube-root it.
''' 

#Imports
from s5c39 import mod_inv as invmod
from s5c33 import unbounded_exp as exp #Used for int_root function

def int_root(n : int, r : int) -> int:
    '''Computes rth root of n. Does not handle complex/Gaussian integers'''
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
    
    raise Exception(f"The root {r} of {n} is not an integer.")

#Haha funny lambda function definition
#probably could have done this from the beginning but generalized solutions are cool.
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
'''
--------------------------------------------------------------------------------
'''