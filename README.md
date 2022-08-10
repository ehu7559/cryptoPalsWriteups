# cryptoPalsWriteups
A currently expanding set of Python programs and guides to the Matasano Cryptopals Challenges. Implemented in Python, made with love.

## Introduction:
I have endeavoured to make my code at least generally understandable to those who are semi-fluent in Python and reading/doing the challenges along with me. However, since I have almost certainly failed to achieve that, each set gets its own writeup file containing a writeup for each of the eight challenges.

This code is written with minimal imports. As of this writing, only vanilla Python libraries are used (base64, time, and random). My goal was to expose as much of the inner workings to cryptographic computations as possible. Whenever it has educational potential (such as Challenge 7, implementing AES-128 ECB), I have endeavored to write my code with as few external imports as possible.

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



## Interesting Things:
Challenges 7, 10, and 18 include by-hand implementations of AES128 in ECB, CBC, and CTR modes respectively.
Mostly written in spare time at work.
