#Challenge 33: Implement Diffie-Hellman

#Much faster, more compact, and very very efficient.
def mod_exp(b, x, n):
    '''Computes residue class b ** x mod n, where all are non-negative integers'''
    #I know you can just use pow, but this is MY implementation! 
    if x == 0:
        return 1 #Simple catch case
    acc = 1 #accumulator
    curr_pow = b
    while x > 0:
        acc *= 1 if (x % 2 == 0) else curr_pow
        acc = acc % n
        curr_pow = (curr_pow ** 2) % n
        x = x // 2
    return acc
