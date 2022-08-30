#Implement the Mersenne Twister

def MT19937_stream(seed: int = 5489) -> int:
    generator = MT19937_generator(initialize_MT19937_state(seed))
    #print(state)
    while True:
        yield(next(generator))

def MT19937_generator(state_buffer : list, index=None) -> function:
    state = [x for x in state_buffer]
    #Set quantities
    w, n, m, r = (32, 624, 397, 31)
    #Pre-evaluated the constant hex expressions for speed.
    a = 2567483615
    u, d = (11, 4294967295) #(11, hex_to_uint("FFFFFFFF"))
    s, b = (7, 2636928640) #(7, hex_to_uint("9D2C5680"))
    t, c = (15, 4022730752) #(15, hex_to_uint("EFC60000"))
    l = 18
    f = 1812433253    

    #Declare State variables
    if index is None:
        index = n

    lower_mask = (1 << r) - 1
    upper_mask = (~lower_mask) % (2 ** w)
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
        yield(temper_transform(state[index]))

        index += 1

def initialize_MT19937_state(seed: int) -> function:
    
    w, n = (32, 624)
    f = 1812433253
    state = [0 for num in range(n)] #This is just an allocator for the state space.

    #Initialize State with seed
    state[0] = (seed % (2 ** w))
    for i in range(1, n):
        #MT[i] := lowest w bits of (f * (MT[i-1] xor (MT[i-1] >> (w-2))) + i)
        state[i] = (f * (state[i - 1] ^ (state[i-1] >> (w - 2)))) % (2 ** w)
    
    return state

def temper_transform(state_val: int) -> int:
    num = state_val
    u, d = (11, 4294967295)
    s, b = (7, 2636928640)
    t, c = (15, 4022730752)
    num = num ^ ((num >> u) & d)
    num = num ^ ((num << s) & b)
    num = num ^ ((num << t) & c)
    num = num ^ (num >> 1)
    return num

#Challenge Code: TEST
if __name__ == "__main__":
    g = MT19937_stream()
    for i in range(10):
        print(str(i)+"\t:\t"+str(next(g)))