#Challenge 23: Clone an MT19937 RNG from its output

from s3c21 import MT19937_stream, MT19937_generator
from time import sleep
from random import randint

def untemper_MT19937(num: int) -> int:
    if num >= 2**32:
        return untemper_MT19937(num % (2**32))
    #Tempering functions called in reverse order.
    return untemper_a(untemper_b(untemper_c(untemper_d(num))))

def untemper_step(value, shift, mask):
    '''Computes x where value = x ^ ((x << shift) & mask)'''

    #Catch case: Compute x where value = x ^ ((x >> shift) & Mask)
    if shift < 0:
        return inverse_32_bits(untemper_step(inverse_32_bits(value), -1 * shift, inverse_32_bits(mask)))
    
    y = value
    m = mask
    acc = 0
    curr = 1 #Power of two
    x = [0 for i in range(32)]
    for i in range(32):
        #Get the bits
        y_i = y % 2
        m_i = m % 2
        
        #Compute x bit and compute it.
        x[i] = y_i if (i < shift) else y_i ^ (x[i-shift] & m_i)
        acc += (curr if x[i] == 1 else 0)
        
        #For next iteration
        y = y >> 1
        m = m >> 1
        curr *= 2

    return acc

def untemper_a(num):
    u, d = (11, 4294967295)
    return untemper_step(num, -1 * u, d)

def untemper_b(num):
    s, b = (7, 2636928640)
    return untemper_step(num, s, b)

def untemper_c(num):
    t, c = (15, 4022730752)
    return untemper_step(num, t, c)

def untemper_d(num):
    return untemper_step(num,  -1 , 2**32 - 1)

def inverse_32_bits(num):
    out = 0
    for i in range(32):
        out += 2**(31-i) if num % 2 == 1 else 0
        num = num // 2
    return out

def clone_MT19937(output):
    state_buffer = [untemper_MT19937(x) for x in output]
    cloned_generator = MT19937_generator(state_buffer)
    return cloned_generator

if __name__ == "__main__":

    #Create generator with a random seed.
    
    chall_seed = randint(0, 2*32 - 1)
    print("Creating MT19937 Pseudo-random Generator")
    chall_stream = MT19937_stream(chall_seed)
    chall_output = [next(chall_stream) for i in range(624)]

    print("Cloning Generator... ", end="")
    cloned_stream = clone_MT19937(chall_output)
    print("Done")
    #Continuously Generate 
    print("Generating and Checking")
    print("INDEX:  GENERATED:      CLONED:         MATCH:")
    for i in range(1000):
        a = next(chall_stream)
        b = next(cloned_stream)
        print(f"{i+1}{' ' * (8 - len(str(i+1)))}{a}{' ' * (16 -len(str(a)))}{b}{' ' * (16 -len(str(b)))}{a==b}", end="\t\t\t\r")
        sleep(0.05)
        assert(a == b)
    print("\nCHALLENGE COMPLETE")