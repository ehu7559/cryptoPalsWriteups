#Challenge 33: Implement Diffie-Hellman
from random import randint

#Much faster, more compact, and very very efficient.
def mod_exp(b: int, x: int, n: int) -> int:
    '''Computes residue class b ** x mod n, where all are non-negative integers'''
    #Very useful for Diffie-Hellman Key Exchange and RSA encryption/decryption
    #I know you can just use pow, but this is MY implementation! (and just as fast) 
    acc = 1 #accumulator
    curr_pow = b % n #Addition of the n enforces b < n. Useful to avoid some unnecessary overheads.
    while x > 0:
        acc *= 1 if (x % 2 == 0) else curr_pow
        acc = acc % n
        curr_pow = (curr_pow * curr_pow) % n
        x = x >> 1
    return acc

def unbounded_exp(b: int, x: int) -> int:
    '''mod_exp without the mod part'''
    acc = 1 #accumulator
    curr_pow = b
    while x > 0:
        acc *= 1 if (x % 2 == 0) else curr_pow
        curr_pow *= curr_pow
        x = x >> 1
    return acc
    
#party class: The endpoints in the key exchange protocol.
class DHParty:

    def __init__(self):
        self.p = None
        self.g = None
        self.secret_key= None
        self.shared_secret = None

    #Initiate DH Handshake (p, g) -> (p, g, A)
    def start_handshake(self, p, g):
        #Set parameter
        self.p = p
        self.g = g

        #Generate secret_key and compute public key.
        self.secret_key = randint(0, self.p - 1)
        return (self.p, self.g, mod_exp(self.g, self.secret_key, self.p))

    #Accept DH Handshake (p, g, A) -> B
    def accept_handshake(self, params):
        p, g, A = params
        #Set parameters
        self.p = p
        self.g = g

        #Compute private and public keys
        self.secret_key = randint(0, self.p - 1)
        self.shared_secret = mod_exp(A, self.secret_key, self.p)

        #Return public key
        return self.get_public_key()

    #Alice takes bob's public key and computes the shared secret
    def finish_handshake(self, pub_key_back):
        self.shared_secret = mod_exp(pub_key_back, self.secret_key, self.p)
        return self.get_secret()

    def get_public_key(self):
        if self.p is None or self.g is None or self.secret_key is None:
            raise Exception("Parameters or Secret Key is missing!")
        return mod_exp(self.g, self.secret_key, self.p)

    def get_secret(self):
        return self.shared_secret

def runDiffieHellman(client:DHParty, server:DHParty, prime: int, generator: int):
    return client.finish_handshake(server.accept_handshake(client.start_handshake(prime, generator)))

# CHALLENGE CODE:
if __name__ == "__main__":  
    chall_p = int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
    chall_g = 2

    print(f"P: {chall_p}")
    print(f"G: {chall_g}")

    Alice = DHParty()
    Bob = DHParty()
    
    a_1 = Alice.start_handshake(chall_p, chall_g)
    print("ALICE SENDS: ")
    print(a_1)
    b_1 = Bob.accept_handshake(a_1)
    print("BOB REPLIES: ")
    print(b_1)
    a_2 = Alice.finish_handshake(b_1)

    print(f"ALICE GOT: \t{Alice.get_secret()}")
    print(f"BOB GOT: \t{Bob.get_secret()}")

    print(f"--- CHALLENGE STATUS: {'COMPLETE' if Alice.get_secret() == Bob.get_secret() else 'ERROR'} ---")