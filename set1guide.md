# Write-up Accompaniment to CryptoPals Challenges: Set 1

## Challenge 1: Convert hex to base64

The challenge asks us to convert hex strings to base64.

This challenge is rather simple. We are simply converting hex to base64 encoding
for this challenge. It's not that hard. Use the base64 library because it's an
absolutely essential function.

## Challenge 2: Fixed XOR

The challenge wants us to implement a function capable of taking two hexadecimal
strings and returning the result of a bit-wise XORing operation.

Wrote the function `hex_xor()`, which takes two hex-strings and decodes them
before performing a bitwise xor of the two buffers with a list comprehension. 
This is still basic programming.

## Challenge 3: Single-byte XOR cipher

The challenge asks us to decrypt the given plaintext, which has been encrypted
by XOR-ing each byte of the plaintext with a single, constant byte value.

The third challenge is the first attack on a cryptosystem, albeit an entirely
trivial one. The approach here brute-forces the 256 keys for each ciphertext and
then determines the highest-scoring plaintext to determine the most likely key.
 
Language classification is a rather complex thing to implement, so a simple
frequency-based analysis is used to score the texts. Based off a well-known
alphabetic frequency distribution, we can assign each alphabetic character a
point value. The scoring function returns the sum of the point values of the
characters within the string. This has the natural effect of preferring texts
which contain more common characters. One could theoretically change the 
function to normalize the score by dividing by length to eliminate the bias
towards longer texts which have more characters. Given the nature of the 
challenge, however, scores are compared only between texts of the same length,
making this unnecessary.

The `crackbyte()` function actually attempts the challenge.

## Challenge 4: Detect single-character XOR

The fourth challenge is conceptually a little bit harder than the third, but is
also substantially easier to code.

What we are looking for is one of the ciphertexts which is encrypted with single
character XOR. To make it more explicit, what we want is a ciphertext which, for
some single-character decryption (0-255), highly resembles English.

Leveraging the code from the previous challenge, it should be relatively simple 
to iterate through the ciphertexts, brute-forcing each one and find the 
ciphertext and key which yield the highest English resemblance. Depending on the
accuracy of the scoring function, certain false positives may outrank the
answer. Thus, I decided to print any plaintexts which scored above a certain
threshold according to my own method. Once the threshold is raised high enough,
the answer should be easy to recognize.

## Challenge 5: Implement repeating-key XOR

This challenge should be immediately recognizable to anyone familiar with the
Vigenere cipher. The only real difference is that this cipher uses bitwise XOR
while the Vigenere cipher uses addition mod 26.

The function body itself is a literal one-liner. Due to the nature of the XOR
operator, the decryption function is equivalent to the encryption function.

## Challenge 6: Break repeating-key XOR

We are now asked to break this Vigenere-like cipher.

The Hamming distance function I wrote is clunky but gets the point across. As
with much of this repository, it was written in my downtime at an internship. My
manager was kind enough to let me code on my work laptop during my free time so
that the monotony of working in tech support did not break my sanity. The 
Hamming Distance between two bytes can be  represented by the number of 1s in 
the binary representation of the bitwise XOR of the two bytes.

The procedure is as follows.
1. Determine Key Length
2. Stripe the ciphertext to reduce to multiple single-character XOR problems
3. Conduct frequency analysis as with single-character XOR to get the key bytes.
4. Decrypt and return.

The key length is determined through an application of Kasiski analysis. 
Kasiski analysis essentially relies on the fact that repetitions of bit/byte
patterns will occur more commonly at regular intervals which are multiples of
the key length. Thus, if we compare blocks of ciphertext with other blocks with
an offset that is an integer multiple of the key length away, then there should
be a noticably lower Hamming distance between the two blocks.

The simple method suggested by the challenge does not guarantee sufficient
accuracy on guessing the key length. It is, as noted in the very angry comments
above the function in the code, "extremely broken".

Instead, I expanded upon the suggestion and computed the average normalized
Hamming distance for any two blocks in the ciphertext. This is, of course, a
very over-engineered process, but given how far off the key length I was, I feel
that this solution was entirely justifiable. Of course, one must be patient.

The striping and de-striping functions are basic data manipulation in Python and
should need no real explanation aside from the fact that they group together the
bytes that were encrypted with the same index of the key.

The frequency analysis is essentially that of challenge 3, applied to each
subset of the ciphertext from the striping functions. If you are still confused,
read challenge 3's writeup again.

After the key-bytes have each been individually computed, the en/de-cryption
function can be called with this key to decrypt.

## Challenge 7: AES in ECB mode

This was probably my first "I'm very proud of myself" achievement, as I actually
implemented AES by hand. My sole import in challenge 7 was base64 to read the
challenge data from the file. My actual AES functions used only vanilla Python.

Those reading the code will note my praise and admiration of my professors. I
owe to them a great debt. Without them, I doubt I would have taken an interest
in cryptology at all.

AES is built of four main steps.
1. SUB BYTES: Bytes are swapped out using a lookup table or matrix math
2. SHIFT ROWS: Bytes are shifted within a block to avoid reductions to 4-byte block
3. MIX COLUMNS: Blocks are multiplied by a matrix in GF(2^8) for diffusion
4. ADD ROUND KEY: Blocks are XOR'd against a pre-computed quantity based on the key


### SUB BYTES:
Implemented with a lookup table for convenience sake, but is, in
actuality, also expressible as a matrix multiplication. TO invert it, simply use
a lookup table that goes the other way. (`SB_TABLE[i] = j`, `INV_SB_TABLE[j] = i`)

### SHIFT ROWS:
Implemented with a mapping for compactness, but can be expressed
as a manipulation of a matrix. For the inverse, use the reverse mapping.

#### SHIFT ROWS:

```
0 4 8 c         0 4 8 c
1 5 9 d  -->    5 9 d 1
2 6 a e         a e 2 6
3 7 b f         f 3 7 b
```

#### INVERSE SHIFT ROWS:

```
0 4 8 c         0 4 8 c
1 5 9 d  -->    d 1 5 9
2 6 a e         a e 2 6
3 7 b f         7 b f 3
```

### MIX COLUMNS:
Multiplies the block by a very special matrix. Multiply
as a normal matrix in GF(2^8). Interestingly, the matrix is such that the 
inverse is simply the same matrix cubed, making `inv_mix_columns()` just three
successive applications of `mix_columns()`

### ADD ROUND KEY:
Adds a round key derived using the Rijndael key schedule algorithm
to the block mod 2, (yep, it's an XOR). The round-keys can be pre-computed once
the key is known, but I am just a tad lazy and don't feel like optimizing it, so
my implementation computes it every time. I hope it will be forgiven in light of
my otherwise rather elegant and clean code. Also the key schedule is a bit of a
mess. The inverse is also just XORing the round key, but the INV_ARK operation
actually performs an `inverse_mix_columns()` on the round key before xor-ing it. It
will be amusingly beautiful once you realize how symmetric AES really is.

**ENCRYPTION:**
```
ADD ROUND_KEY_0
For i in 0 -> 10:
    sub bytes, shift rows, mix_columns, and add round_key_i
sub bytes, shift rows, and add round_key 10
```
**DECRYPTION:**
```
Add round_key_10
for i in 9 -> 0
    inv sub bytes, inv shift rows, inv mix columns, inv add round_key_i
inv sub bytes, inv shift rows, and add round_key_0
```

The full specs of AES can be found on Wikipedia. I'm just a little too tired to
write a full explanation. My code is also rather neatly formatted for this one
in particular, so I recommend giving it a read. I won't bore you to death with a
detailed explanation of it.

As noted in the code, writing code to encrypt AES ECB was not yet necessary, but
was very handy in future challenges.

## Challenge 8: Detect AES in ECB mode

Much, much easier than challenge 7. Look for a ciphertext with a repeated block.

Honestly there's not much to say here. This property of ECB is actually the
source of its name: Electronic Code Book. For a given key, ECB is essentially a
glorified lookup table. Thus, any identical plaintext blocks will then yield
identical ciphertext blocks, with the same displacement from each other. 

## Set 1 Closing Remarks:
Set 1 is an interesting introduction to practical cryptography. It began with
extremely basic code but also built upon our ability to do low-level data
manipulation. In challenge 7, we implemented AES-128 ECB mode in its entirety,
with no imports except when the challenge's format required us to use `base64`.

I hope this has been interesting so far. This is my first long-form writeup
series. (I actually learned most of my Markdown while writing this document in
particular!)
