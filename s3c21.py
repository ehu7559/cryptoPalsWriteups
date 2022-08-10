#Implement the Mersenne Twister

def bytes_to_uint(buffer):
    buf = bytearray(buffer)
    acc = 0
    curr = 1
    while len(buf) > 0:
        acc += buf.pop() * curr
        curr *= 256
    return acc

def hex_to_uint(hex):
    return bytes_to_uint(bytes.fromhex(hex))

def MT19937_stream(seed: int = 5489) -> int:
    
    #Set quantities
    w, n, m, r = (64, 312, 156, 31)
    #Pre-evaluated the constant hex expressions for speed.
    a = 13043109905998158313 #hex_to_uint("B5026F5AA96619E9")
    u, d = (11, 4294967295) #(11, hex_to_uint("FFFFFFFF"))
    s, b = (7, 2636928640) #(7, hex_to_uint("9D2C5680"))
    t, c = (15, 4022730752) #(15, hex_to_uint("EFC60000"))
    l = 18
    f = 1812433253    
    
    #Declare State variables
    index = n
    state = [0 for num in range(n)] #This is just an allocator for the state space.
    lower_mask = (1 << r) - 1
    upper_mask = (~lower_mask) % (2 ** w)
    
    #Initialize State with seed
    state[0] = (seed % (2 ** w))
    for i in range(1, n):
        #MT[i] := lowest w bits of (f * (MT[i-1] xor (MT[i-1] >> (w-2))) + i)
        state[i] = (f * (state[i - 1] ^ (state[i-1] >> (w - 2)))) % (2 ** w)

    #Yielding Loop
    while True:
        #If state is exhausted
        if index == n:
            #Generate next n bytes of state through twist!
            for i in range(0, n-1):
                x = (state[i] & upper_mask) + (state[(i + 1) % n] & lower_mask)
                xA = x >> 1
                if not x%2 == 0:
                    xA = xA ^ a
                state[i] = (state[(i + m) % n] ^ xA)
            index = 0
            
        #compute and yield value
        y = state[index]
        y = y ^ ((y >> u) & d)
        y = y ^ ((y << s) & b)
        y = y ^ ((y << t) & c)
        y = y ^ (y >> 1)

        yield y
        index += 1

#Challenge Code: TEST
if __name__ == "__main__":
    g = MT19937_stream()
    for i in range(10):
        print(str(i)+"\t:\t"+str(next(g)))
        