# Write-up Accompaniment to CryptoPals Challenges: Set 4

## Challenge 25: 

We again see a variation on an One-Time Pad reuse. This is not a very difficult
challenge. By setting some byte in the message to be a known value, we can then
XOR the corresponding byte of the ciphertext (given that CTR mode does not have
the property of diffusion of the ciphertext that other modes have) to obtain the
value of the corresponding byte of the keystream. 

Repeating this for each byte, we can obtain a copy of the original keystream.
With this, we XOR it against the original ciphertext to decrypt it.

## Challenge 26:

In an extension of the previous challenge, we can also use a plaintext with
chosen values to recover a segment of the keystream. Then, XOR-ing this part of
the keystream against the plaintext we wish to transplant into the message, we
obtain an encrypted form of our crafted payload to splice into the ciphertext.

## Challenge 27:

This challenge exploits a set of poor decisions in implementing CBC-mode AES
encryption. In this case, the communicants have decided to use the key as the
IV as welll. In addition, there is an (apparently common) information leak in
the form of the error message when the plaintext contains an unusual character.
The error message contains the decrypted plaintext.

Given an intercepted message and at least one vulnerable eendpoint, it is 
possible to not only recover the text, but recover the key as well.

Following the instructions should make it clear why we conduct the attack the
way it it is done.

When `C1` is decrypted and returned in error, the first block will be XORed with
the IV (in this case, our key!) and the third block will be XORed with 
`00000000000000000000000000000000`, which is a null operation. Thus, we have two
quantities: `KEY XOR P1'` and `P1'`. XORing these two blocks together reveals
the key.

## Challenge 28:

This challenge asks us to implement a SHA-1 keyed MAC protocol.

SHA-1 is a now-deprecated cryptographic hash algorithm. The pseudocode is, as
stated on the challenge, available on Wikipedia. In the interest of completeness
and thoroughness, however, I have included a brief description below.

The SHA-1 hash consists of a 160-bit internal state, broken up in to 5 32-bit
registers. The message/data to be hashed is broken into 512-bit chunks. These
chunks are sequentially hashed and each of the 5 32-bit words in the hashed
value are then added to the internal registers mod 2^32.

The final block is padded by appending `0x80` (to indicate that the length is a
whole number of bytes) and then padded with zeroes until 8 bytes short of the
block length (512 bits). The length is then encoded in the remaining 8 bytes as
a 64-bit unsigned integer. This chunk is subsequently hashed as normal.

The hashing operation itself consists of 
1. An extension of the 512-bit chunk into 80 32-bit words.
2. Five registers (a, b, c, d, e) are initialized with the values of the state
hash. The registers are 32-bit words, thus taking the entire 160-bit state.
3. The five registers are subjected to 80 rounds of various bitwise operations.
4. They are then added to the original hash's words mod 2^32.

The SHA1 keyed MAC authenticates a message with a secret key by prepending the
key to the message before hashing it. Without knowledge of the key, it is
difficult for the attacker to compute a hash matching a given text. This helps
detect tampering attacks.

## Challenge 29:

SHA-1's cumulative nature is such that the next block is added to the hash of
the previous message, meaning that, to add to a message hash, the hash is equal
to hashing the original message and then ingesting the new data in the message.

Let the situation be such that one has access to a message authentication oracle
and an authenticated message with the hash and plain message.

The primary complicating factor is the padding on the last block and the encoded
length at the end of the processed message. In an ordinary hash, this would be
trivial. Unfortunately, we also have to contend with a key of unknown length and
unknown value.

Brute-forcing the key alone would not be feasible. Instead, we will simply 
attempt to find the length of the key through repeated trial and error. Since we
are trying to be authenticated, we can take advantage of the fact that the
authentication protocol is presumed to be such that a client knows whether or
not the message was accepted as authentic. We can thus simply try messages with
progressively longer key lengths until our forged message is authenticated.

The "glue padding" can be computed as long as you have access to the initial
hash and a guess at the key length.


## Challenge 30:

We repeat the challenge with MD4. Those who have read through the previous
challenges' code should have little trouble understanding this one. I doubt that
my code here needs any explanation not found in the challenge description. The
MD4 code was based off a cursory search.

## Challenge 31:

Given the nature of the challenges, I have resorted to using lambdas rather than
actually implementing a web server.

Early-exit string comparisons allow us to determine how many consecutive bytes
of the string were correct. Using this knowledge, we can test each byte's values
and select the one with the longest comparison time (indicating that the
comparator function checked another byte).

This works best on POSIX-based systems, as Windows' timekeeping leaves much to
be desired.

## Challenge 32:

When the delay becomes far less measurable, we can resort to repeated comparison
operations to make the time difference more appreciable and also tune out the
variance in actual comparison time. This does, however, substantially increase
the time required to carry out an attack. Fortunately, we are blessed by the
lower time per byte anyway, resulting in a runtime comparable to that of the
previous challenge.

[ IN PROGRESS ]
