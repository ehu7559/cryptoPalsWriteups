# Write-up Accompaniment to CryptoPals Challenges: Set 5

**Note:**
```
At this point, full understanding of these problems generally requires some
basic familiarity with computational complexity theory, discrete mathematics,
and algorithm design. Those who have finished a bachelor's degree in computer
science will be fine, although they may occasionally have to do some light
reading to supplement these writeups for f
```

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
those who have already spent enough time playing around with Diffie Hellman or are sufficiently familiar with basic number theory. 

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
against currently known algorithms to solve it such that the solution is computationally infeasible to compute.

`g` is the generator element mod `N`, with `g = 2` in this case.

`k` is a coefficient here for protection against a 2-for-1 guessing attack, and
thus helps maintain the computational difficulty of the problem.

`I` is the email or any other identifier used to indicate to the server who the client is claiming to be.

`P` here is a shared secret known to both parties, but which cannot be transmitted in the clear due to its secrecy. The client will attempt to prove its knowledge of this value to the server.

**Server Initial Computation:**  
```
S
Generate salt as random integer
Generate string xH=SHA256(salt|password)
Convert xH to integer x somehow (put 0x on hexdigest)
Generate v=g**x % N
Save everything but x, xH
```

The server generates a random salt of random length as a buffer and ingests it
into a SHA-256 hash with the password. This hash is then parsed into an integer.
The quantity `v` is then generated by raising the generator `g` to the power of
`x`. The hash and its integer representation are then discarded, but the salt
and v are saved. This process can be done after the initial agreement, allowing
the hash to be stored, although the password may be saved if one wishes to use a
different salt each time.

**Client initiates the authentication process**
```
C->S
Send I, A=g**a % N (a la Diffie Hellman)
```

The client initiates a Diffie-Hellman-esque handshake. The value of `a` can be
an arbitrary value. `A` and `a` are saved for later computations.

**Server Responds to Diffie Hellman with salt**
```
S->C
Send salt, B=kv + g**b % N
```

The server responds with a modification of the Diffie Hellman computation. It
adds the salted generator power `g`, multiplied by the `k` coefficient for 
security, to the standard `B` found in Diffie-Hellman. It also passes the salt
to the client for computation.

**Client and Server Computations**
```Markdown
S, C
Compute string uH = SHA256(A|B), u = integer of uH
C
Generate string xH=SHA256(salt|password)
Convert xH to integer x somehow (put 0x on hexdigest)
Generate S = (B - k * g**x)**(a + u * x) % N
Generate K = SHA256(S)
S
Generate S = (A * v**u) ** b % N
Generate K = SHA256(S)
```

The client and server both compute `uH`. Note that this is not a shared secret
as the values of `A` and `B` are both transmitted in the clear. This is then 
converted into an integer `u`.

The client then computes the `xH` value known to the server using the salt 
provided by the server in its previous step before converting it to the integer
`x`. This is vital to computing `v` on the client side. Note that `v` is never 
actually transmitted as it is used to prove knowledge of the secret. The client
generates the following value for S.

```
S = (B - k * g**x) ** (a + u * x) % N
  = (B - kv) ** (a + ux) % N
  = (g**b) ** (a + ux) % N
  = (g**ba * g**bux) % N
```

The server then computes the same value of S using A.
```
S = (A * v**u) ** b % N
  = (g**a * (g**x)**u) ** b % N
  = (g**a * g**ux) ** b % N
  = (g**ba * g**bux) % N
```

As one can see, these two values *should* match. As `x` is composed of a SHA-256
of the salt and the password (and the salt is transmitted), the password is the
key to making `x` secret. It is not, in any practical sense, possible to compute
`S` without knowing `x`. Note, further, that `x` is never transmitted alone,
instead being transmitted using `v`, thus being protected by the discrete
logarithm problem's computational difficulty. Furthermore, the protocol then
protects `x` by folding it into the Diffie-Hellman process, such that not even
`v` is ever exposed in tranmission, instead being incorporated into a different
value.

Both sides then compute the hash of this `S` value which will be checked for
authentication, computing `K` as the SHA-256 hash of `S`.

**Client sends K for Verificaiton:**
```
C->S
Send HMAC-SHA256(K, salt)

S
Send "OK" if HMAC-SHA256(K, salt) validates
```

The client attempts a hash-based message authentication of K and the server
responds accordingly.

## Challenge 37: Break SRP with a zero key

To compute the value of `x` without knowing the password, one must find a way to
control/predict the value of `K`. SHA-256 is, as of writing, resistant to 
collisions, especially when the input is not known, so controlling the server's 
computation of `S` is the best option. As the server computes `S` using the 
formula `S = (A * v**u) ** b % N`, using `A` to control the value of S is
useful. Using `0` for `A` will force `S` to be `0`, requiring the client to
compute `K = SHA-256(0)` and then use the salt to compute the HMAC to 
authenticate without the password. Any value such that `A % N = 0` will also
yield the same results. 

This challenge ends with a statement that sounds almost accusational:
```
Almost every implementation of SRP we've ever seen has this flaw; if you see a
new one, go look for this bug.
```

Indeed, this was true of my own implementation.

## Challenge 38: Offline dictionary attack on simplified SRP

`Work in Progress`

## Challenge 39: Implement RSA

RSA (Rivest, Shamir, and Adleman's algorithm) is the current (as of this 
writing) standard algorithm for asymmetric encryption. Its successor (Kyber) is
resistant to quantum-enabled attacks, but as large-scale quantum computing is 
currently unavailable to the general public (although one must assume it is
already possible that the intelligence community has a working quantum computer
with the required scale/capabilities.), it is currently still in widespread
use and is safe for communications which need not remain secret in the future.

**A cryptographic aside:**
```Markdown
The advent of "Store Now, Decrypt Later" tactics has rendered RSA-encrypted
communications ultimately insecure within perhaps the next decade. This is, as
one might imagine, a serious problem, as the new Kyber encryption scheme built
to resist quantum computing attacks is still not in widespread use. Thus, one
must now assume that any asymmetric encryption they use is, at its core, only a
temporary protection. Shor's algorithm is already capable of efficient integer
factorization, and RSA is no longer a safe encryption scheme, even before the
widespread adoption of quantum computing. RSA use must cease immediately if the
secret is to remain future-proof.

This is a terrifying prospect. Widespread adoption of quantum computers will, I
am certain, at the very least up-end geopolitics, to put it rather mildly. I
cannot imagine another outcome.

Should we still have computers post-apocalypse, however, it will still be 
feasible to use AES encryption, as Grover's algorithm (which reduces the time
complexity of a naive exhaustive search to O(sqrt(n)) rather than O(n)) does not
provide a super-polynomial speedup. Some form of AES derivative will suffice for
symmetric key encryption, although key-sizes will need to be doubled to provide
the same level of security.

Thank you for reading this unhinged tangent. Please stare into the abyss with me
and appreciate the eldritch horror that is mathematics.
```

RSA relies on the computational complexity of the integer factorization problem.
The factorization problem is NP-hard, and thus for conventional computers there
does not currently exist a known factorization algorithm that is bound by
polynomial time. (RSA is actually NP-complete, meaning that, while it can be
verified in polynomial time, it is as "hard" as any other computational problem
in the problem space NP).

While most public key exponents (conventionally denoted by `e`) are the sum of
a few powers of 2 (Usually things like 3, 17, or 65537) to make sure encryption
is quick, it is still well worth using a repeated-squaring technique to speed up
exponentiation. For further speedup, use the `pow` function in Python, which is
actually written in C and pre-compiled.

*(As a Python programmer I cry a little bit whenever I'm reminded of this)*

## Challenge 40: Implement an E=3 RSA Broadcast attack

This challenge makes use of the Chinese Remainder Theorem to decrypt a broadcast
encrypted with three or more different RSA keys.

A passive observer can obtain the plaintext using the ciphertexts resulting from
encrypting the message with three or more distinct keys.
