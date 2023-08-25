#Challenge 39: Implement RSA

#Imports
from s5c33 import mod_exp

#EGCD Function, uses Extended Euclidian Algorithm
def gcd(a, b):
    a, b = abs(a), abs(b)
    if a < b:
        a, b = b, a
    while a % b:
        a, b = b, a % b
    return b

#Multiplicative Inverse Calculator
def mod_inv(x, n):
    '''Computes the multiplicative inverse of x mod n'''
    #The time complexity is O(log(n))
    #A quick search of the internet did not yield any 'faster' algorithms.
    #That being said, I have made an effort to keep the space requirements reasonable.
    #Compute GCD using EEA, saving values along the way.
    x = x % n
    if x == 0 or n == 0:
        raise Exception("Modular inverse requires all integers to be positive.")

    a, b = n, x
    eea_stack = [a, b]
    
    #Generate the stack.
    while a % b != 0:
        a, b = b, a % b
        eea_stack.append(b)

    #Raise an exception if the two numbers are not relatively prime
    if b != 1:
        raise Exception("Modular Inverse of " + str(x) + " does not exist mod " + str(n))

    eea_stack.pop() #Remove the last number (assumed/guaranteed to be a 1)

    high = 1
    low = -1 * (eea_stack[-2] // eea_stack[-1])
    while len(eea_stack) > 2:
        eea_stack.pop() #Remove an element
        ratio = eea_stack[-2] // eea_stack[-1]
        high, low = low, (high - (ratio * low))

    return low % n

#RSA key-gen
def compute_rsa_key(p : int, q : int):
    '''Given two NIST primes, computes an RSA public and private key'''
    #It is the duty of the idiot using my code (me) to make sure the primes are selected properly.
    #If you use composite numbers here, you've fucked up.
    #If you pick weak primes, the code will work but your key will be weak.
    #Constants
    n = p * q                   #RSA modulus
    phi_n = (p - 1) * (q - 1)   #Euler's Totient of modulus. Order of the multiplicative group U(n)
    e = (1 << 16) + 1           #Public key exponent
    d = mod_inv(e, phi_n)       #Private key exponent    

    pub_key = (n, e)
    priv_key = (n, d)
    return (pub_key, priv_key)

def parse_int_big_endian(buf):
    '''Reads a big-endian integer from buffer'''
    acc = 0
    for i in range(len(buf)):
        acc = acc << 8 #byte shift
        acc += buf[i]
    return i

def encode_int_big_endian(num):
    acc = []
    while num:
        acc.insert(0, num % 256)
        num = num >> 8 #Shift byte
    return bytes(acc)

#Encryption Method
def encrypt_rsa(message, public_key):
    n, e = public_key
    m_encoded = parse_int_big_endian(message)
    if m_encoded >= n:
        raise Exception("Message does not fit in key modulus")
    return mod_exp(m_encoded, e, n)

def decrypt_rsa(ciphertext, private_key):
    n, d = private_key
    if ciphertext >= n:
        raise Exception("Ciphertext does not fit in modulus")
    plain_encoded = mod_exp(ciphertext, d, n)
    return encode_int_big_endian(plain_encoded)

#Prime-generation left out because it's computationally expensive and also just plain complicated.

#Main function
if __name__ == "__main__":
    print("This is an implementation challenge. There is no expected output.")
    print("--- CHALLENGE STATUS: COMPLETE ---")
