#Get lines

def probablyECB(data):
    blocks = []
    num_blocks = len(data) //16

    #Chunkify it
    for i in range(num_blocks):
        blocks.append(data[16 * i: 16 * (i + 1)])
    
    for i in range(num_blocks - 1):
        for j in range(i+1, num_blocks):
            if blocks[i] == blocks[j]:
                return True
    return False

#CHALLENGE CODE
if __name__ == "__main__":    
    f = open("8.txt","r")
    ls = f.readlines()
    f.close()
    for line in [l for l in ls if probablyECB(l.encode("ascii"))]:
        print(line)