#A playground for testing out various cryptography things

def gcd(a, b):
    if a < b:
        a, b = b, a #Swap
    while a%b != 0:
        a, b = b, a % b
    return b

def fast_lin_possible_primes():
    yield 2
    yield 3
    i = 6
    while True:
        yield i - 1
        yield i + 1
        i += 6

def list_primes():
    prim_gen = fast_lin_possible_primes()
    prim_prod = next(prim_gen)
    tmp = next(fast_lin_possible_primes)
    while True:
        while gcd(prim_prod, tmp) > 1:
            tmp = next(prim_gen)
        yield tmp
        prim_prod *= tmp

