#Challenge 41: Implement unpadded message recovery oracle

def craft_payload(ciphertext : int, public_exponent : int, public_modulus : int, s : int):
    return (pow(s, public_exponent, public_modulus) * ciphertext) % public_modulus

def recover_plaintext(retrieved_plaintext : bytes, public_modulus : int, s : int):
    return (pow(s, -1, public_modulus) * retrieved_plaintext) % public_modulus 

if __name__ == "__main__":
    pass
    