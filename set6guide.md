# Write-up Accompaniment to CryptoPals Challenges: Set 6

Here begins the end of the original challenges.
Some basic familiarity with number theory is recommended.
Those who have taken an undergraduate cryptology course will be fine.
(At the very least, I was fine!)

## Challenge 41: Implement unpadded message recovery oracle

Given a captured ciphertext and a one-time decryption oracle, we can trick the
decryption oracle into helping us obtain the plaintext.

The decryption oracle is the only way to use the private key.

As RSA plaintext and ciphertexts are, at their core, unsigned integers, we may
use multiplication to decrypt the same ciphertext twice.

```Markdown
Let the key be (n, e, d).
Let the message be m.
Let the captured ciphertext c = m^e
The server will not decrypt c twice.

We may craft a payload which decrypts to m * s, where s is some integer constant
relatively prime to n, so that, by multiplying by the inverse of s mod n, we can
obtain m without having the server decrypt c twice.

As the oracle is the function f(x) -> x ^ d mod n = x ^ (1/e) mod n, we can then
obtain the ciphertext that would yield this number.
Let c' = s^e * c mod n

Upon decryption of c' by the oracle, we can obtain m with the previously
described method.
```

## Challenge 42: Bleichenbacher's e=3 RSA Attack

Bleichenbacher's e=3 RSA signature forgery attack is quite interesting.
It utilizes a weakness in implementations of RSA signature verifiers which do
not properly check the padding.

The PKCS1.5 standards specify the following format

```
0x0001ff..ff00 + ASN.1_DATA + HASH
```

where the prefix contains enough bytes of `0xff` to pad the data to a full block
of RSA (1024 bits in this case, although RSA implementations also support block
sizes of 2048 and 4096).

A simple verifier implementation would parse through the header before assuming
that the ASN.1 data and the hash are the end of the block and return the verdict
based on the hash's correctness.

The issue with this is that the header can be shortened to 0x0001ff00 (or
0x0001ffff00 depending on the implementation) which would leave a large number
of empty bytes after the hash with which to make the signature's integer
representation a perfect cube so that, with the public exponent being e = 3, the
signature will be an integer that does not overflow the modulus when cubed.

The approach taken in `s6c42.py` fills the empty bytes after the hash with
`0xff` before taking the floored cube root of the payload. As it is highly
improbable that the constructed payload is a perfect cube already, the signature
will decrypt to something somewhat lower. There are, however sufficient bytes of
`0xff` to prevent the actual hash bytes from being affected. An equally valid
approach would have been to use `0x00` instead and add 1 to the floored cube
root.

## Challenge 43: Implement DSA

This challenge asks us to implement the DSA (Digital Signature Algorithm):
 
The following information is derived from the [Wikipedia entry for DSA](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm)

### DSA Algorithm

#### Parameter Generation (Agreed upon by all users)

Let ***N*** be the modulus length in bits.

An approved cryptographic hash function is selected.
Let **H** be this hash function with output length **|H|**.
The conventional hash function is SHA-1, although SHA-2 is also approved for use in the current digital signature schemes.
**H** must produce at least ***N*** bits of output.

Let ***L*** be the key length in bits. Standards generally require ***L*** be a multiple of 64.
The NIST800-57 standard specifies ***L*** = 2048  or ***L***=3072 for keys being used past 2010 or 2030 respectively.

Let ***q*** be an ***N***-bit prime.

Let ***p*** be an ***L***-bit prime such that ***p*** = 1 *mod* ***q***.

Let ***h*** be a random integer from range {2, ..., ***p*** - 2}.
***h*** is often set to 2.

Let ***g*** = ***h***^(***p*** - 1 / ***q***) mod ***p***. If ***g*** = 1, re-select ***h*** and attempt again.

The shared parameters are ***(p, q, g)***.

#### Key Generation (Per user)

Each user computes their key as follows:

- Select an integer ***x*** from range {1, ... , ***q*** - 1} as a private key.
- Compute ***y*** = ***g***^***x*** *mod* ***p*** as the corresponding public key.

#### Key Distribution

A signator will publish their public key ***y***.
It is not necessary to transmit ***y*** securely given it is public.

#### Message Signing:

A message ***m*** may be signed as follows:

Let ***k*** be a random integer from {1, ..., ***q*** - 1}

Let ***r*** = (***g***^*k mod* ***p***) *mod* ***q***. If ***r*** = 0, select a different ***k*** and attempt again.

Let ***s*** = (***k***^(-1) * (**H**(***m***) + ***xr***)) *mod* ***q***. As with before, if the result is 0, reselect ***k*** and attempt again.

The signature is (***r***, ***s***).

#### Verification:

A verifier perofrms the following steps to verify that a signature (r, s)
- Assert ***r*** is a natural in **Z_*p*** and ***s*** is a natural in **Z_*q***.
- Compute ***w*** where ***w*** is the inverse of ***s*** *mod* ***q***.
- Compute ***u_1*** where ***

***g*** = ***h***^(***p*** - 1 / ***q***) mod ***p***
implies ***g*^*p*** = ***h***^(***p*** - 1 / ***q***) mod ***p***

This further implies that ***g*** is a generator of the integers mod ***p***.
(In math terms, **Z_*p*** = **<*g*>**)

The 