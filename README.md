# cryptoPalsWriteups
A currently expanding set of Python programs and guides to the Matasano Cryptopals Challenges. Implemented in Python, made with love.

## Introduction:
I have endeavoured to make my code at least generally understandable to those who are semi-fluent in Python and reading/doing the challenges along with me. However, since I have almost certainly failed to achieve that, each set gets its own writeup file containing a writeup for each of the eight challenges.

This code is written with minimal imports. As of this writing, only vanilla Python libraries are used (such as base64, time, and random). My goal was to expose as much of the inner workings to cryptographic computations as possible. Whenever it has educational potential (such as Challenge 7, implementing AES-128 ECB), I have endeavored to write my code with as few external imports as possible in order to present all of the necessary information for the reader in the source code.

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

## Modules of Interest (the challenges most imported from):
```
Challenge 7:    AES-128 ECB (Advanced Encryption Standard, 128-bit, Electronic Code Book mode)
Challenge 10:   AES-128 CBC (Advanced Encryption Standard, 128-bit, Cipher Block Chain mode)
Challenge 18:   AES-128 CTR (Advanced Encryption Standard, 128-bit, Counter mode)
Challenge 21:   MT19937 PRNG (Mersenne-Twister 19937 Psuedo-Random Number Generator)
Challenge 28:   SHA-1 (Secure Hash Algorithm 1)
Challenge 33:   Diffie Hellman Key Exchange
```

## Completion Status:
```
Set 1:  1   2   3   4   5   6   7   8
Set 2:  9   10  11  12  13  14  15  16
Set 3:  17  18  19  20  21  22  23  24
Set 4:  25  26  27  28  29      31  32
Set 5:  33  34
Set 6:  
```
