#Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection

#Imports:
from s2c10 import encrypt_AES_CBC_128, decrypt_AES_CBC_128
from s2c9 import trim_padding
from s4c28 import SHA1
from s5c33 import DHParty
from random import randint

def encode_int(num):
    output = bytearray()
    while num > 0:
        output.insert(0, num % 256)
        num = num // 256
    return bytes(output) 

def secret_message(message, secret_num):
    helper_iv = bytes([randint(0, 255) for i in range(16)])    
    helper_key = bytes.fromhex(SHA1.hash(encode_int(secret_num)).encode("ascii"))[0:16]
    return (encrypt_AES_CBC_128(message, helper_key, helper_iv), helper_iv)

def reveal_message(secret_msg, secret_num):
    ciphertext, init_vector = secret_msg
    helper_key = bytes.fromhex(SHA1.hash(encode_int(secret_num)).encode("ascii"))[0:16]
    return trim_padding(decrypt_AES_CBC_128(ciphertext, helper_key, init_vector))

#Challenge Code:
if __name__ == "__main__":
    chall_p = int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff",16)
    chall_g = 2

    #Get Parties
    Alice = DHParty()
    Bob = DHParty()

    #A->M
    #Send "p", "g", "A"
    a_m_1 = Alice.start_handshake(chall_p, chall_g)

    #M->B
    #Send "p", "g", "p"
    m_b_1 = (a_m_1[0], a_m_1[1], a_m_1[0])
    
    #B->M
    #Send "B"
    b_m_1 = Bob.accept_handshake(m_b_1)

    #M->A
    #Send "p"
    m_a_1 = m_b_1[0] #Send p again!    
    Alice.finish_handshake(m_a_1)

    #A->M
    #Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
    msg = "You have completed Set 5, Challenge 33! This is a generic message.".encode("ascii")    
    print("Alice Sent: " + msg.decode("ascii"))
    a_m_2 = secret_message(msg, Alice.get_secret())

    #M->B
    #Relay that to B
    m_b_2 = a_m_2

    #B->M
    #Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
    b_got = reveal_message(m_b_2, Bob.get_secret())
    print("Bob Recieved: "+ b_got.decode("ascii"))

    #M->A
    #Relay that to A
