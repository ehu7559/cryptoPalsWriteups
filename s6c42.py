#Challenge 42: Bleichenbacher's e=3 RSA Attack

from s5c40 import cube_root #Uses the integer cube-root lambda from challenge 40.
from s4c28 import SHA1

def encode_uint_big_endian(num : int, length : int) -> bytes:
    assert(num >= 0)
    if num >= pow(256, length):
        raise Exception(f"Unsigned Integer {num} cannot fit in {length} bytes!")
    
    output = bytearray(length)
    ptr = -1
    while num:
        output[ptr] = num & 0xFF
        ptr -= 1
        num = num >> 8
    return bytes(output)

def decode_uint_big_endian(buffer : bytes) -> int:
    num = 0
    for i in range(len(buffer)):
        num = num << 8 #Bitshift
        num += buffer[i]
    return num

def forge_rsa_signature_e3(message : bytes) -> bytes:

    #Intialize message with the shortest header possible
    sig_plain = bytearray([0, 1 , 255, 0]) #Signature header

    #Get hash of message
    ASN_1_DER = bytes.fromhex("3021300906052b0e03021a05000414")
    #The SHA-1 hash algorithm appears to be standard for digital signatures.
    message_hash = bytes.fromhex(SHA1.hash(message))
    sig_plain.extend(ASN_1_DER)
    sig_plain.extend(message_hash)
    
    #pad the signature block to 1024 bits as per the challenge
    while len(sig_plain) < 128:
        sig_plain.append(255)
    #Take the encoded version of the floored cube root.
    sig_crypt = encode_uint_big_endian(cube_root(decode_uint_big_endian(sig_plain)), 128)
    return bytes(sig_crypt)

def check_signature_weak(signature : bytes, message : bytes) -> bool:
    plain_sig = encode_uint_big_endian(decode_uint_big_endian(signature) ** 3, 128)

    read_ptr = 0
    #parse through the preamble (Finite state automaton)
    if plain_sig[read_ptr] != 0:
        return False
    read_ptr += 1
    if plain_sig[read_ptr] != 1:
        return False
    read_ptr += 1
    #Skips over an arbitrary nonzero amount of 0xff bytes
    while plain_sig[read_ptr] == 255:
        read_ptr += 1
    if plain_sig[read_ptr] != 0:
        return False
    read_ptr += 1
    
    #Check for the ASN.1 header 
    #I *would* match using a parser but I'm too tired.
    SHA_1_ASN_1_DER = bytes.fromhex("3021300906052b0e03021a05000414")
    for i in range(len(SHA_1_ASN_1_DER)):
        if SHA_1_ASN_1_DER[i] != plain_sig[read_ptr]:
            return False
        read_ptr += 1
    
    #Extract the SHA-1 hash
    sig_hash = bytes(plain_sig[read_ptr : read_ptr + 20]).hex()

    #Hash the message
    check_hash = SHA1.hash(message)

    return bool(sig_hash == check_hash)

if __name__ == "__main__":
    chall_text = "hi mom"
    print(f"CHALLENGE TEXT: \"{chall_text}\"")
    chall_message = chall_text.encode()
    forged = forge_rsa_signature_e3(chall_message)
    print(forged.hex())
    print(encode_uint_big_endian(decode_uint_big_endian(forged) ** 3, 128).hex())
    print("MESSAGE SHA1: " + ("." * 24) + SHA1.hash(chall_message))
    is_valid = check_signature_weak(forged, chall_message)
    print(f"SOLUTION ACCEPTED: {is_valid}")
    print(f"--- CHALLENGE STATUS: {'COMPLETE' if is_valid else 'ERROR'} ---")