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
        x = x // 2
    return acc
```

**Protocol Implementation:**  
I have (against my own better judgement) implemented this as an object-oriented
protocol for the sake of clarity and readability. The code should be legible on
its own, so I shall spare the reader a lengthy explanation.

## Challenge 34:

Here we implement a Man-in-the-middle attack on Diffie-Hellman with parameter
injection.