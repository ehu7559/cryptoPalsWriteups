from s1c7 import decrypt_block_128

#Padding oracle yaaaay
def is_valid_pad(plaintext: bytes) -> bool:
    if len(plaintext) % 16 > 0 or len(plaintext) < 16:
        return False #Improper length
    #Truncate to last 16 bytes
    plaintext = bytearray(plaintext[-16:])
    pad_len = plaintext[-1]
    if pad_len > 16 or pad_len == 0:
        return False
    for i in range(pad_len):
        if plaintext.pop() != pad_len:
            return False
    return True

def is_valid_CBC_padding(data, key, iv):
    while len(data) > 16:
        iv, data = data[:16], data[16:]
    assert(len(data) == 16)
    data = decrypt_block_128(data, key)
    data = bytes([data[i] ^ iv[i] for i in range(16)])
    return is_valid_pad(data)

if __name__ == "__main__":
    print("This is an implementation challenge. There is no expected output.")
    print("--- CHALLENGE STATUS: COMPLETE ---")
