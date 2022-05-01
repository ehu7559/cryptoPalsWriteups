#Cryptopals Challenge 13

from s1c7 import encrypt_AES_ECB_128, decrypt_AES_ECB_128

CHALLENGE_STATUS = "INCOMPLETE"

#Parsing Routine
def parse_cookie(c):
    output = "{\n"
    lines = c.split("&")
    for l in lines:
        kv = l.split("=")
        output += "\t" + kv[0] + ":" + kv[1] + "\n"
    output +="}"
    return output

#Encryption Oracle
def encrypt_oracle(aes_key):
    return lambda x : encrypt_AES_ECB_128(x, aes_key)

#Decryption Oracle
def decrypt_oracle(aes_key):
    return lambda x : decrypt_AES_ECB_128(x, aes_key)

#profile_for function
def profile_for(email, oracle):
    pass

#Gain admin block

#Attack function

#TEST FUNCTIONS:
def test_parse_cookie():
    print(parse_cookie("email=heath@cookinramenwithheath.com&role=ramencook&uid=2"))

#Main
if __name__ == "__main__":
    #Test
    test_parse_cookie()

    #create an oracle for encryption

    #Create an oracle to decrypt answer to check.

    #Attack the oracle

    #Decrypt using the oracle and check
    
    print("--- CHALLENGE STATUS: " + CHALLENGE_STATUS + " ---")
    pass