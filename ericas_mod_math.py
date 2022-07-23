#Discrete (mostly modular) math functions
#Written for academic purposes.
#there are probably much better implementations out there, but i think i've done
#a decent job with these.

#Quick testing suite
from random import randint
def get_reasonable_num_small():
    return randint(1, mod_exp(2, 16))
def get_reasonable_num_med():
    return randint(mod_exp(2, 16), mod_exp(2, 32))
def get_reasonable_num_big():
    return randint(mod_exp(2, 32), mod_exp(2, 64))
def test_to_failure(generator, solver, verifier, threshold=100):
    '''(func() -> list, func(list) -> a, func(list, a) -> bool, int) -> list
        Repeatedly generates up to threshold data sets, computes a solution with
        the solver being tested, and then runs the verifier. Returns the first
        list of inputs that failed, alongside the solver's output. Will return
        None on a "successful" test with no failures.'''
    for i in range(threshold):
        g = generator()
        s = solver(g)
        v = verifier(s)
        if not v:
            return [g, s]
    return None

#A hyper-compact and non-iterative version of GCD.
#Can also be implemented with a list
def gcd(a, b):
    a, b = max(a, b), min(a,b)
    while b > 1 and a % b > 0:
        a, b = b, a % b
    return b        

#Not sure if this may somehow be faster given Python's bullshittery.
def gcd_list(a,b):
    output = [max(a, b), min(a,b)]
    while output[-1] > 1 and output[-2] % output[-1] > 0:
        output.append(output[-2] % output[-1])
        output.pop(0)
    return output[-1]

#Optimized modular exponentiation
def mod_exp(b, x, n=None):
    #Performed about as well as pow(b, x, n) in testing.
    if b == 0:
        return 0
    if b < 0:
        return 0 if n is None else mod_exp(b%n, x, n)
    if x == 0:
        return 1 #Simple catch case
    if x < 0:
        return 0 if n is None else mod_exp(mod_inv(b, n), -x, n)

    acc = 1 #accumulator
    curr_pow = b #The power to multiply by
    
    while x > 0:
        #Multiply by the current b**x if necessary
        acc *= 1 if (x % 2 == 0) else curr_pow
        curr_pow = (curr_pow ** 2)
        
        #Take modulus if present
        if n is not None:
            acc = acc % n
            curr_pow = curr_pow % n
        x = x // 2
    
    return acc

#Pretty good modular inverse calculator
#Uses Extended Euclidian Algorithm
#Mimics by-hand calculations
def mod_inv(a, n):
    ''' Computes modular inverse of a mod n'''
    
    #Catch cases
    if a * n == 0 or gcd(a, n) > 1: #Math/logic impossibilities
        return 0
    if a != a % n: #Clamps down on the integers on interval [0, n)
        return mod_inv(a % n, n)
    
    #Generate extended euclidian algorithm stack (Used in calculations)
    eea_stack = [n, a]
    while eea_stack[-1] > 1:
        eea_stack.append(eea_stack[-2] % eea_stack[-1])

    #prepare
    eea_stack.pop(-1) #Remove the 1

    #Compute Factors
    high_fac = 1
    low_fac = -1 * (eea_stack[-2] // eea_stack[-1]) #Initial division

    #This loop expands and simplifies equations, representing with larger and larger coefficients.
    while len(eea_stack) > 2:
        eea_stack.pop(-1)
        high_fac, low_fac = low_fac, (high_fac - (low_fac * (eea_stack[-2]//eea_stack[-1]))) 
        
    return (low_fac % n)
