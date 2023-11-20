#Challenge 46: RSA parity oracle
from base64 import b64decode
from s1c3 import defang_str_bytes
from s5c39 import compute_rsa_key

def get_rsa_parity_oracle(priv_key):
    n, d = priv_key
    return lambda x: pow(x, d, n) % 2 == 0

def encode_bigint(num : int):
    buf = []
    while num:
        buf.append(num & 0xFF)
        num = num >> 8
    buf.reverse()
    return bytes(buf)

def attack_padding_oracle(ciphertext : int, pub_key, oracle):
    n, e = pub_key
    numerator = 1
    denominator = 2 #Denominator is always a power of 2
    c_iter = n
    display_width = len(str(n))//2
    display_bytes = None

    #Attack Loop
    while c_iter:
        #Multiply
        ciphertext = (ciphertext << e) % n
        numerator = (numerator << 1) + (-1 if oracle(ciphertext) else 1)
        denominator = denominator << 1

        #Extra-precise big num calculation (Using floats loses precision as ciphertext increases)
        product = numerator * n
        modulus = product % denominator
        guess = product // denominator
        precision_adjustor = int((2 * modulus)//denominator) #Rounds correctly :)
        guess += precision_adjustor

        #Convert to hex
        display_bytes= encode_bigint(guess)
        display_string = defang_str_bytes(display_bytes).replace("\n", "*").replace("\t", "*")
        display_string += " " * (display_width - len(display_string))

	    #Print for fun, with return end character
        print(display_string, end="\r")
        c_iter = c_iter >> 1
    
    return defang_str_bytes(display_bytes)

if __name__ == "__main__":
    
    #Challenge key and constants
    chall_text = b64decode("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")

    #primes from an online generator
    chall_p = 2184688214199944940572178118737957758567768830012330751908949430119579796261927377922312330032599601736675236020841616011228127871000514893410391231048963
    chall_q = 5918350910874206079300049026623847458968878679437900649752689209474515557977548260463551756044135095047754815596923345925182792817076223272726887871710891

    #Generate keypair from the primes
    chall_keys = compute_rsa_key(chall_p, chall_q)
    pub_key, priv_key = chall_keys
    n, e = pub_key
    _, d = priv_key

    #Encrypt the challenge text
    ciphertext = pow(int(chall_text.hex(), base=16), e, n)

    chall_oracle = get_rsa_parity_oracle(priv_key)
    print("BEGINNING RSA PARITY ORACLE ATTACK...\n")
    chall_flag = attack_padding_oracle(ciphertext, pub_key, chall_oracle)
    print("\nFINISHED\n")
    print(f"FLG: {chall_flag}")
    print(f"SOL: {chall_text.decode()}\n")
    print(f"--- CHALLENGE STATUS: {'COMPLETE' if (chall_flag == chall_text.decode()) else 'FAILURE' } ---")
