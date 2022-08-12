#Clone an MT19937 RNG from its output

from s3c21 import MT19937_stream, MT19937_generator, temper_transform
from s3c21 import temper_a, temper_b, temper_c, temper_d
from time import sleep
from random import randint

def untemper_MT19937(num):
    if num >= 2**32:
        return untemper_MT19937(num % (2**32))
    #Tempering variables
    u, d = (11, 4294967295)
    s, b = (7, 2636928640)
    t, c = (15, 4022730752)

    #Untemper Step: y_4 = y_3 ^ (y_3 >> 1)
    y_3 = untemper_step(num,  -1 , 2**32 - 1)
    #Untemper Step: y_3 = y_2 ^ ((y_2 << t) & c)
    y_2 = untemper_step(y_3, t, c)
    #Untemper Step: y_2 = y_1 ^ ((y_1 << s) & b)
    y_1 = untemper_step(y_2, s, b)
    #Untemper Step: y_1 = y_0 ^ ((y_0 >> u) & d)
    y_0 = untemper_step(y_1, -1 * u, d)
    return y_0

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
        acc += curr if x[i] == 1 else 0
        
        #For next iteration
        y = y // 2
        m = m // 2
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
    untemper_step(num,  -1 , 2**32 - 1)

def inverse_32_bits(num):
    out = 0
    for i in range(32):
        out += 2**(31-i) if num % 2 == 1 else 0
        num = num // 2
    return out

def clone_MT19937(output):
    state_buffer = [untemper_MT19937(x) for x in output]
    cloned_generator = MT19937_generator(state_buffer, 0)
    for i in range(624):
        old_output_i = next(cloned_generator)
        print(f"Checking Output: {old_output_i} : {output[i]}")
        sleep(0.1)
        #if old_output_i != output[i]:
            #print(f"ERROR DETECTED AT INDEX {i}")
    print("Successfully Cloned Generator!")
    return cloned_generator

if __name__ == "__main__":
    print("Testing Untempering: Step A")
    for i in range(624):
        tempered = temper_a(i)
        untempered = untemper_a(i)
        if tempered != untempered:
            print("A is broken")
            print(f"{i} : {tempered} = {untempered}")
            break
    for i in range(624):
        tempered = temper_b(i)
        untempered = untemper_b(i)
        if tempered != untempered:
            print("B is broken")
            print(f"{i} : {tempered} = {untempered}")
            break
    for i in range(624):
        tempered = temper_b(i)
        untempered = untemper_b(i)
        if tempered != untempered:
            print("B is broken")
            print(f"{i} : {tempered} = {untempered}")
            break