# cryptoPalsWriteups
A currently expanding set of Python programs and guides to the Matasano Cryptopals Challenges. Implemented in Python, made with love, stress, and unbridled ambition.

## DISCLAIMER:
This repository contains source code for implementations of various cryptographic protocols, some of which are, at the time of writing, still standard. The implementations are based on a combination of course study, mathematical texts, and reference to well-known open standards. The code in this repository is known to contain multiple vulnerabilities and lacks the safeguards required for truly secure cryptography. Under no circumstances should this be used for actual security. The author of this repo takes no responsibility for those who fail to heed this warning. Use well-reputed cryptographic libraries/implementations. Don't trust some rando's implementation, and don't use your own.

## Introduction:
I have endeavoured to make my code at least generally understandable to those who are semi-fluent in Python and reading/doing the challenges along with me. However, since I have almost certainly failed to achieve that, each set gets its own writeup file containing a writeup for each of the eight challenges.

This code is written with minimal imports. As of this writing, mostly non-cryptographic Python libraries are used (such as base64, time, and random), with the occasional import of SHA-256 for compactness reasons. My goal was to expose as much of the inner workings to cryptographic computations as possible. Whenever it has educational potential (such as Challenge 7, implementing AES-128 ECB), I have endeavored to write my code with as few external imports as possible in order to present all of the necessary information for the reader in the source code.

I highly recommend you proceed in ascending order. Challenges often import code from previous, related challenges, especially past Challenge 7. The context will make things much more understandable.

## Recommended Use:

For the viewer's pleasure, I recommend having the following open side-by-side when viewing a given challenge:

### For a given Challenge (Set A, Challenge B)
Open the following (replacing A and B with the appropriate numbers)
```
- set[A]guide.md (the file containing the writeup)
- s[A]c[B].py (the file containing the code for the challenge)
- https://cryptopals.com/sets/[A]/challenges/[B]
```

## Note on simulated "servers"

As networking is not the focus of these challenges, most of the communications
protocols in the challenges has been removed.

Where applicable, "oracle"-type servers have been replaced by lambda functions.

Peer-to-peer communications (like Diffie Hellman) have been simulated step by
step rather than utilizing network transmissions.

These modifications to the challenge do not fundamentally alter the underlying
cryptological concepts covered in the challenges.

## Modules of Interest (the challenges most imported from):

The following challenges are primarily concerned with implementation of
protocols that are used in later exercises, and are thus of particular interest
to students of cryptosystems.

```
Challenge 7:    AES-128 ECB (Advanced Encryption Standard, 128-bit, Electronic Code Book mode)
Challenge 10:   AES-128 CBC (Advanced Encryption Standard, 128-bit, Cipher Block Chain mode)
Challenge 18:   AES-128 CTR (Advanced Encryption Standard, 128-bit, Counter mode)
Challenge 21:   MT19937 PRNG (Mersenne-Twister 19937 Psuedo-Random Number Generator)
Challenge 28:   SHA-1 (Secure Hash Algorithm 1)
Challenge 33:   Diffie Hellman Key Exchange
Challenge 39:   RSA
```

## Completion Status:
```
Set 1:  1   2   3   4   5   6   7   8
Set 2:  9   10  11  12  13  14  15  16
Set 3:  17  18  19  20  21  22  23  24
Set 4:  25  26  27  28  29      31  32
Set 5:  33  34      36  37      39  40
Set 6:  41  42

Current Priorities:
 - Refactoring and cleaning up Challenges 1 - 34 [In progress]
 - Challenges 38 - 40 [Under development]
```

## Thanks and Recognition:
```text
My dearest thanks to the following:
 - My professors for teaching me the material that enabled me to understand
    these challenges.
 - My friends for listening to me ramble about cryptology late into the night.
 - My managers/mentors for encouraging me to keep pursuing this passion of mine.
```