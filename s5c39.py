'''
Implement RSA
There are two annoying things about implementing RSA. Both of them involve key generation; the actual encryption/decryption in RSA is trivial.

First, you need to generate random primes. You can't just agree on a prime ahead of time, like you do in DH. You can write this algorithm yourself, but I just cheat and use OpenSSL's BN library to do the work.

The second is that you need an "invmod" operation (the multiplicative inverse), which is not an operation that is wired into your language. The algorithm is just a couple lines, but I always lose an hour getting it to work.

I recommend you not bother with primegen, but do take the time to get your own EGCD and invmod algorithm working.

Now:

Generate 2 random primes. We'll use small numbers to start, so you can just pick them out of a prime table. Call them "p" and "q".
Let n be p * q. Your RSA math is modulo n.
Let et be (p-1)*(q-1) (the "totient"). You need this value only for keygen.
Let e be 3.
Compute d = invmod(e, et). invmod(17, 3120) is 2753.
Your public key is [e, n]. Your private key is [d, n].
To encrypt: c = m**e%n. To decrypt: m = c**d%n
Test this out with a number, like "42".
Repeat with bignum primes (keep e=3).
Finally, to encrypt a string, do something cheesy, like convert the string to hex and put "0x" on the front of it to turn it into a number. The math cares not how stupidly you feed it strings.
'''

#Imports
from s5c33 import mod_exp

#EGCD Function, uses Extended Euclidian Algorithm
def gcd(a, b):
    a, b = abs(a), abs(b)
    if a < b:
        a, b = b, a
    while a % b:
        #It can be proven that gcd(a, b) = gcd(b, a % b)
        '''
        let x = gcd(a, b)
        let c, d be such that a = cb + d, where d is in Z_b
        x | a --> x | (cb + d)
        x | b --> x | cb AND x | (cb + d) --> x | d
        I shall refrain from including a verbose, thorough proof for brevity.
        '''
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
    pass