'''
Here is the opening stanza of an important work of the English language:

Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal
Encrypt it, under the key "ICE", using repeating-key XOR.

In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.

It should come out to:

0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.
'''

#Main function
def xor_vigenere(filename, key):
    
    #Prepare key
    kb = bytes(key, "ascii")
    kn = len(kb)
    ki = 0
    #Open in/out files
    f_in = open(filename, "rb")
    f_out = open(filename + ".xorcrypt", "wb")

    #stream encryption
    f_bytes = f_in.read()
    for f_byte in f_bytes:
        if f_byte == 13: #Escapes CRLF from Windows
            continue
        out_bytes = (bytes([f_byte ^ kb[ki]]))
        print(out_bytes.hex(), end="")
        ki = (ki + 1) % kn
        
    #Close both files
    f_in.close()
    f_out.close()

xor_vigenere(input("Enter Filename: "), input("Enter Key: "))