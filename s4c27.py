#Recover the key from CBC with IV=Key

#Imports
from random import randint
from s2c10 import decrypt_AES_CBC_128, encrypt_AES_CBC_128

#Validation function
def is_valid_ciphertext(data, key, iv):
    plain_data = decrypt_AES_CBC_128(data, key, iv)
    for a in plain_data:
        if a not in range(127):
            return False 
    return True

def get_server_oracle(key, iv):
    return lambda x : bytes() if is_valid_ciphertext(x, key, iv) else decrypt_AES_CBC_128(x, key, iv) 

#Attack Function
def attack(intercepted_message, decryption_server):
    if len(intercepted_message) < 16:
        print("ERROR: Message length is insufficient to conduct attack")
        return
    payload = bytearray()
    payload.extend([intercepted_message[i] for i in range(16)])
    payload.extend(bytes(16))
    payload.extend([intercepted_message[i] for i in range(16)])
    newplain = decryption_server(payload)
    if len(newplain) == 0:
        print("ERROR: Message transformation did not trigger server failure")
    recovered_key = bytes([newplain[i] ^ newplain[i+32] for i in range(16)])
    return recovered_key

#Challenge Code
if __name__ == "__main__":
    #Generate key
    print("GENERATING KEY/IV VALUES...")
    chall_key = bytes([randint(0, 255) for i in range(16)])
    chall_iv = chall_key

    #Server generation
    print("SETTING UP CHALLENGES...")
    chall_server = get_server_oracle(chall_key, chall_iv)
    #Generate sender message
    plain_message = bytes([ord(c) for c in "This message is a placeholder. Please make sure that this is long enough to carry out the attack."])
    encrypted_message = encrypt_AES_CBC_128(plain_message, chall_key, chall_iv)

    #Perform attack
    print("PERFORMING ATTACK...")
    cracked_key = attack(encrypted_message, chall_server)
    cracked_text = decrypt_AES_CBC_128(encrypted_message, cracked_key, cracked_key)
    print(cracked_text.decode("ascii"))