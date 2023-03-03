# Write-up Accompaniment to CryptoPals Challenges: Set 5

## Challenge 33: Implement Diffie-Hellman

We begin our work with an implementation of the Diffie-Hellman key exchange
protocol. It depends on the discrete logarithm problem, for which an efficient
algorithm or solution is not currently known.

**Diffie-Hellman Key Exchange Protocol**
```
Pre-agreement:
Prime p, Generator g (mod p)

Private secret generation:
Alice: Selects integer a mod p
Bob:   Selects integer b mod p

Exchange:
Alice -> Bob:   [g^a mod p]
Bob   -> Alice: [g^b mod p]

Shared Secret Computation:
Alice: Computes [g^(ba) mod p]
Bob:   Computes [g^(ab) mod p]

The shared secret is g^(ab)=g^(ba)
```

**Modular Exponentiation:**  
Modular exponentiation takes advantage of the rules of modular arithmetic to
compute powers mod some integer without storing the massive power first.

Additionally, we can implement an efficient algorithm by using repeated squaring
of the base to reduce the number of multiplications required. Rather than a
for loop simply repeatedly multiplying an accumulator by the base mod p, we
instead multiply by the base to the power of increasing powers of 2. In other
words, we can break the power down into binary and multiply together the proper
powers of b computed through repeated squaring.

```
def mod_exp(b: int, x: int, n: int) -> int:
    '''Computes residue class b ** x mod n, where all are non-negative integers'''
    if x == 0:
        return 1 #Simple catch case
    acc = 1 #accumulator
    curr_pow = b
    while x > 0:
        acc *= 1 if (x % 2 == 0) else curr_pow
        acc = acc % n
        curr_pow = (curr_pow ** 2) % n
        x = x >> 1
    return acc
```

I believe this to be the algorithm used in the canon Python implementation of
the `pow()` function, although given that many of Python's keywords are written
in C, I'm not entirely sure. At any rate, this is an exponential speedup, at a
constant space complexity no less!


**Protocol Implementation:**  
I have (against my own better judgement) implemented this as an object-oriented
protocol for the sake of clarity and readability. The code should be legible on
its own, so I shall spare the reader a lengthy explanation.

```
TODO: Redo thie Diffie-Hellman challenges in a functional style instead.
Who in their right mind would use object oriented programming? You're awful.
```

## Challenge 34:

Here we implement a Man-in-the-middle attack on Diffie-Hellman with parameter
injection. The reader should optimally be familiar enough with high school math
to figure out what's going on.

## Challenge 35:

I have elected to skip this one. It does not provide much useful knowledge to
those who have already spent enough time playing around with Diffie Hellman. 

I will return to this challenge at a later date.

## Challenge 36:

This challenge involves implementation of the SRP (Secure Remote Password)
Protocol. 

Secure Remote Password utilizes the same computationally complex problem as 
Diffie-Hellman key exchange: the dicrete logarithm problem.

A pre-shared secret in the form of a password, here treated as a string. 

N is a NIST prime. In essence, on that is sufficiently large to make a
brute-force attempt at the discrete logarithm problem infeasible.

The constant `g` is specified to be a generator of the set of in integers mod N.
Since N is a NIST prime, g can be almost any integer mod N, just not 1 or 0. In
this case, g is selected as g=2.

The constant `k` is a value that must be determined and agreed upon by the
parties. In the standards for SRP-6, the value is predetermined as `k = 3`, but
SRP-6a allows the computation of k with the setup's hash function. The hash 
function here is the standard one: SHA-256.

The point of the SRP protocol is to compute a shared secret based on the 
password. This technique is known as "Password-Authenticated Key Exchange", or
"PAKE".

The Diffie-Hellman Key Exchange protocol is vulnerable to offline brute-force 
attacks. Given sufficient time, an observer to the Diffie-Hellman Key Exchange
could compute the shared secret through a trivial brute-force. (Simply test
increasing powers of the generator `g` until one of the two parties' public
portion is obtained, then raise the other public "key" to that power to compute
the shared secret)

The SRP protocol incorporates the password into the interaction such that it is
not possible for an observer to discern any shared secrets using only the
information transmitted during the protocol.

### The SRP Protocol (Annotated):

**Initial Agreement:**  
```
C & S
Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
```
The client and server agree on the vital parameters of the protocol.

`N` is a NIST prime, sufficiently large and with the desirable mathematical
properties such that the discrete logarithm problem is sufficiently guarded
against primes.

`g` is the generator element mod `N`, with `g = 2` in this case.

`k` is a coefficient here for protection against a 2-for-1 guessing attack, and
thus helps maintain the computational difficulty of the problem.

