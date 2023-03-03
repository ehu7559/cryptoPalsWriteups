# Write-up Accompaniment to CryptoPals Challenges: Set 3

## Challenge 17: The CBC padding oracle

The padding oracle attack uses the knowledge of whether or not the plaintext has
valid PKCS#7 padding at the end to obtain the decrypted form of a given
ciphertext without knowledge of the key.

A padding oracle can occur in multiple forms, such as a direct error message, a
slightly different (but still vague) error message, or even just slightly
different behavior (such as a slightly different response time). Any chance,
randomness, or imprecision in padding validity determination can be mitigated by
repeating the padding validation enough to make false determinations unlikely.

Using the properties of CBC, it is possible to manipulate a single bit of the
ciphertext to alter the corresponding bit in the next block's plaintext. Using
this, we can then repeatedly alter the ciphertext in order to find the values
which give the last block valid padding of different lengths. One might begin to
see why set 16 was placed right before this.

Given an *n*-block ciphertext, we can attack each of the *n* blocks separately
through the following process.

The desired endings (paddings) for the block are

```
..............................01
............................0202
..........................030303
........................04040404
......................0505050505
....................060606060606
..................07070707070707
................0808080808080808
..............090909090909090909
............0A0A0A0A0A0A0A0A0A0A
..........0B0B0B0B0B0B0B0B0B0B0B
........0C0C0C0C0C0C0C0C0C0C0C0C
......0D0D0D0D0D0D0D0D0D0D0D0D0D
....0E0E0E0E0E0E0E0E0E0E0E0E0E0E
..0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F
10101010101010101010101010101010
```

The attack will thus involve modifying the preceding block in order to produce
progressively longer valid pads to determine the values of bytes of plaintext.
Cracking the text right-to-left allows the attacker to crack one byte at a time,
using previous rounds' results to compute the values needed to produce the bytes
of the next padding.

Increment the initialization vector's last byte until the padding oracle 
indicates valid padding. If `Y ^ X_15 = 0x01` , then the post-decryption 
`X_15 = Y ^ 0x01`. Next the attacker will use this to find the IV value that 
gives a padding of `0202` and use those results to calculate the block that will
give a padding of  `030303` and so on, eventually recovering the entire block.

## Challenge 18: Implement CTR, the stream cipher mode

AES CTR (Counter) mode uses a counter and a nonce to generate a pseudorandom
stream of bytes which is then XOR-ed against the plaintext to encrypt it.

Each block of 16 bytes is XORed with the following block:
```
encrypt_AES_ECB( [64-bit nonce, 64-bit counter], key)
```

After every 16 bytes of encryption, the counter is incremented by 1 and the
next block is generated in the same way.

An advantage is that the stream-cipher nature of CTR mode means that no padding
is necessary. The proper number of bits is read from the bitstream for the
encryption/decryption process. This also has the added side effect of making
encryption and decryption identical in nature, potentially reducing the size of
the program.

Nonce-key pairs should not be reused under any circumstances, as the next two
exercises will make abundantly clear.

*As a side note, one may very soon see why exercises 3-6 were included*

## Challenge 19: Break fixed-nonce CTR mode using substitutions

Here we see the first of two attacks against nonce reuse in AES CTR mode.

This challenge essentially boils down to an attack on a reused One-Time Pad.

Once you have obtained multiple ciphertexts, applying an attack technique used
on the Vigenere cipher should yield you a recognizable plaintext. The key can
then be tweaked to reveal the full message.

## Challenge 20: Break fixed-nonce CTR mode statistically

Reapply the technique from Challenge 19 in the more traditional Vigenere cipher
attack style. As the plaintexts are of relatively uniform length, the rest of
the text should be easily guessable based on the words.

## Challenge 21: Implement the MT19937 Mersenne Twister RNG

This challenge is relatively straightforward, hence the short description on the
challenge page.

The Mersenne Twister's main loop consists of three primary components:

- a state buffer to represent the internal state of the "registers".
- a twist() operation for the shift feedback register
- a tempering transform to distribute bits evenly throughout a word of output.

When initialized, the MT19937 Mersenne Twister RNG takes a seed and initializes
its internal state buffer to *n* words of *w* bits each. The M19937 uses the 
values 624 and 32 for *n* and *w* respectively. 

The values in the internal state are subjected to a tempering transform before
being yielded as output. The tempering transform is a collection of bitshifts,
bitwise AND operationss, and bitwise XOR operations. This has the effect of more
evenly distributing 1s and 0s within the output.

Each time a 32-byte word is read from the RNG, it increments its internal index
counter until all 624 words of the internal state have been read. Once the state
buffer has been exhausted, the MT19937 RNG performs the `twist()` operation upon
its internal state buffer, producing a new state buffer as a function of the
previous state. It then resets the index counter to 0 and begins anew.

This twist operation is deterministic and the randomness pool, once the MT19937
has been initialized, is entirely contained within the state buffer. Two MT19937
instances with the same internal state buffer will produce the same output.

## Challenge 22: Crack an MT19937 seed

This challenge tasks the programmer with brute-forcing the seed of an MT19937
RNG seeded with the time of its creation.

It is not very feasible to compute the seed of an RNG based on its output.
However, if the output is known and the seed is known to fall within a small
set of values (such as a short-ish time interval as seen in this challenge), it
is possible to determine the seed through brute force. Simply generate output
for each possible value of the seed until a match is found.

## Challenge 23: Clone an MT19937 RNG from its output

This challenge essentially compromises the MT19937's unpredictability given a
certain amount of output.

Given a single consecutive state buffer's worth of output, it is possible to
recover the original internal state of the generator and thus predict any future
output. Doing this constitutes "cloning" the MT19937.

This requires a function to reverse the tempering transform, which I must admit 
I did not implement very efficiently.

### An interesting side note

It's actually possible to clone the state with just over two state buffers of
output. One simply needs to be able to detect which interval(s) of 624 outputs
come from the same state buffer, which can be accomplished by brute force. This
removes the challenge's artificial requirement that the sample output be exactly
one state buffer's worth of output with nothing in front of it.

One might also theoretically be able to determine the boundaries between two
states by using a side-channel timing attack to detect the relatively expensive
and slow `twist()` operation.

## Challenge 24: Create the MT19937 stream cipher and break it

The MT19937 stream cipher can be interpreted as a (much) weaker alternative to
AES CTR mode, with the "key" being a seed instead.

The same attacks will work on it as seen in previous challenges. I won't bore
the reader with a lengthy discussion of them given that challenges 18 through 20
focused on those attacks already, with more to come.

## Set 3 Closing Remarks:
Well this was entertaining! To be honest, this set took me a while because I did
not want to implement the MT19937 RNG. (Incidentally, I did find a writeup on
the internet by someone else who also left these challenges for later.)

We are also almost done with AES attacks. These challenges have been extremely
useful in my learning. 