def probablyECB(data: bytes) -> bool:
    '''Determines whether or not a given plaintext is likely to be ECB. Just looks for any repeated blocks.'''
    if (len(data) % 16):
        return False #Not being composed of 16-byte blocks indicates it probably isn't even an AES ciphertext

    blocks = []
    num_blocks = len(data) // 16

    #Chunkify it
    for i in range(num_blocks):
        blocks.append(data[16 * i: 16 * (i + 1)])
    
    for i in range(num_blocks - 1):
        for j in range(i + 1, num_blocks):
            if blocks[i] == blocks[j]:
                return True
    return False

#CHALLENGE CODE
if __name__ == "__main__":    
    with open("8.txt","r") as f:
        ls = f.readlines()
        for line in [l for l in ls if probablyECB(l.encode("ascii"))]:
            print(line)