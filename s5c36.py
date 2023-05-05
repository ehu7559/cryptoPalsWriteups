#Implement Secure Remote Password (SRP) Protocol
from random import randint
from hashlib import sha256
from s5c33 import mod_exp, unbounded_exp as exp
from s5c34 import encode_int

#Salted Hashing function:
def hash_sha256(data : bytes, salt=None):
    output_hash = sha256()

    #ingest hash salt.
    if salt is not None:
        output_hash.update(bytes(salt))
    
    #ingest data
    output_hash.update(bytes(data))

    #Return hex digest in string form.
    return output_hash.hexdigest()

'''
C & S
Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
TYPES (For this implementation)
N : int
g : int
k : int
I : string
P : string
'''
def agree_params(N:int , g:int, k:int, I:str, P:str):
    return (N, g, k, I, P)

'''
S
Generate salt as random integer
Generate string xH=SHA256(salt|password)
Convert xH to integer x somehow (put 0x on hexdigest)
Generate v=g**x % N
Save everything but x, xH
'''
def server_init(init_params):
    #Unpack parameters
    N, g, k, I, P = init_params

    #Generate Salt (I have elected to generate it as a bytes object.)
    hash_salt = bytes([randint(0, 255) for i in range(randint(0,255))])
    
    #Hash and convert to integer
    xH = hash_sha256(bytes(P, "ascii"), hash_salt)

    #Convert to integer
    x = int(xH, 16)

    #Modular exponentiation
    v = mod_exp(g, x, N)

    #Return stuff to save
    return (init_params + (hash_salt, v))

'''
C->S
Send I, A=g**a % N (a la Diffie Hellman)
'''
def client_send_A(init_params: tuple , a: int):
    N, g, k, I, P = init_params

    A = mod_exp(g, a, N)

    #Pack into params and Unpack
    return (init_params + (a , A), A)

'''
S->C
Send salt, B=kv + g**b % N
'''
def server_send_B(post_init_params : tuple, b : int):
    #Unpacking
    N, g, k, I, P, salt, v = post_init_params 
    
    #Compute B
    B = int((((k * v) % N) + mod_exp(g, b, N)) % N)
    
    #Save parameters and leave stuff to send.
    return (post_init_params + (b, B), (salt, B))

'''
S, C
Compute string uH = SHA256(A|B), u = integer of uH
C
Generate string xH=SHA256(salt|password)
Convert xH to integer x somehow (put 0x on hexdigest)
Generate S = (B - k * g**x)**(a + u * x) % N
Generate K = SHA256(S)
S
Generate S = (A * v**u) ** b % N
Generate K = SHA256(S)
'''
def client_side_compute(client_compute_params, received_B):
    #Unpack
    N, g, k, I, P, a, A = client_compute_params
    salt, B = received_B

    uH = hash_sha256(encode_int(B), encode_int(A)) #Takes advantage of salting mechanism to avoid bytes-object manipulation
    u = int(uH, 16) #I feel like adding "0x" to the front involves too much memory overhead.

    xH = hash_sha256(bytes(P, "ascii"), salt)
    
    #Convert xH to integer x somehow (put 0x on hexdigest)
    x = int(xH, 16)

    S_base = ((B % N) - ((k * mod_exp(g, x, N))%N) % N)
    S_power_of_a = mod_exp(S_base, a, N)
    S_power_of_x = mod_exp(S_base, x, N)
    S_power_of_ux = mod_exp(S_power_of_x, u, N)
    S = (S_power_of_a * S_power_of_ux) % N

    S = encode_int(S)
    K = hash_sha256(S)
    
    #Save the only things you need (K, salt)
    return (K, salt)

def server_side_compute(params, received_A):
    #Unpack params
    N, g, k, I, P, salt, v, b, B = params
    A = received_A
    
    #Compute string uH = SHA256(A|B), u = integer of uH
    uH = hash_sha256(encode_int(B), encode_int(A)) #Takes advantage of salting mechanism to avoid byte manipulation
    u = int(uH, 16) #I feel like adding "0x" to the front involves too much memory overhead.

    #Generate S = (A * v**u) ** b % N
    S_base = (A * mod_exp(v, u, N))% N 
    S = mod_exp(S_base, b, N)

    #Generate K = SHA256(S)
    S = encode_int(S)
    K = hash_sha256(S)
    
    return (K, salt)
'''
C->S
Send HMAC-SHA256(K, salt)
'''
def client_send_salted_HMAC(params):
    K, salt = params
    K = bytes.fromhex(K)
    return (K, hash_sha256(K, salt))

'''
Send "OK" if HMAC-SHA256(K, salt) validates
'''
def server_verdict(params, client_HMAC):
    K, salt = params
    client_K, client_hash = client_HMAC
    K = bytes.fromhex(K)
    server_hash = hash_sha256(K, salt)
    return (K == client_K) and (client_hash == server_hash)

#Demo/test function
def run_test(test_params, test_constants):
    test_a, test_b               = test_constants
    print("Server Initializing...", end="")
    server_initialized           = server_init(test_params)
    print("Done")
    print("Client Initializing, Sending A...", end="")
    client_initialized, client_A = client_send_A(test_params, test_a)
    print("Done")
    print("Server Sending B... ", end="")
    server_post_B, server_B      = server_send_B(server_initialized, test_b)
    print("Done")
    print("Client Side Computing... ", end="")
    client_side_computation      = client_side_compute(client_initialized, server_B)
    print("Done")
    print("Server Side Computing... ", end="")
    server_side_computation      = server_side_compute(server_post_B, client_A)
    print("Done")
    print("Client Sending HMAC... ", end="")
    client_send_HMAC             = client_send_salted_HMAC(client_side_computation)
    print("Done")
    print("Server Verifying HMAC... ", end="")
    server_get_verdict           = server_verdict(server_side_computation,client_send_HMAC)
    print("Done")
    print("Validated: " + str(server_get_verdict))

def generate_test_params():
    #Generates some test parameters.
    #Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)

    #Some are hardcoded due to NIST standards/requirements and how annoying they would be to generate.
    chall_N = int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
    g = 2
    k = 3
    I = "test@example.com"
    P = generate_password()
    test_parameters = (chall_N, g, k, I, P)
    a = randint(0, 2**32 - 1)
    b = randint(0, 2**32 - 1)
    return(test_parameters, (a, b))

def generate_password():
    password_length = randint(1, 32)
    acceptable_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    output = ""
    for i in range(password_length):
        output += acceptable_chars[randint(0,len(acceptable_chars) - 1)]
    return output

#Challenge code (Main body)
if __name__ == "__main__":
    run_params, run_constants = generate_test_params()
    run_test(run_params, run_constants)
