def probablyECB(data: bytes) -> bool:
    '''Determines whether or not a given plaintext is likely to be ECB. Just looks for any repeated blocks.'''
    if (len(data) % 16):
        return False #Not being composed of 16-byte blocks indicates it probably isn't even an AES ciphertext

    blocks = set()
    num_blocks = len(data) // 16

    #Chunkify it
    for i in range(num_blocks):
        block = data[16 * i: 16 * (i + 1)].hex()
        if block in blocks:
            return True
        blocks.add(block)
    return False

#CHALLENGE CODE
if __name__ == "__main__":    
    with open("challenge-data/8.txt","r") as f:
        for l in f.readlines():
            l_b = bytes.fromhex(l)
            if probablyECB(l_b):
                print(l)