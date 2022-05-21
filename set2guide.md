# Write-up Accompaniment to CryptoPals Challenges: Set 2

## BRIEFING:

This is the first of several sets on block cipher cryptography. This is bread-and-butter crypto, the kind you'll see implemented in most web software that does crypto.

This set is relatively easy. People that clear set 1 tend to clear set 2 somewhat quickly.

Three of the challenges in this set are extremely valuable in breaking real-world crypto; one allows you to decrypt messages encrypted in the default mode of AES, and the other two allow you to rewrite messages encrypted in the most popular modes of AES.

## Challenge 9: Implement PKCS#7 padding
I ripped this one entirely out of the Challenge 7 code I wrote. In the interest
of completeness, though I've included it here with a description:

PKCS#7 padding standards (as specified in RFC 5652) specify the following:

Let `n` be the number of bytes of padding needed to make the plaintext length a
multiple of the block size (16 here). All padding bytes will have value `n`.

If the plaintext is a perfect multiple of the block size, an entire block of
padding is used for clarity. Otherwise, it would potentially be ambiguous as to
whether or not the end of the plaintext was padding or not.

Certain implementations apparently use `0x00` instead of the `n` for the padding
other than the last byte, which retains the value `n`. The `trim_padding()`
function handles either one because it openly does not care about it.

## Challenge 10: Implement CBC mode
CBC mode XORs a block of plaintext with the previous block of ciphertext before
encrypting it. This provides somewhat more security as it does not readily
reveal repeated blocks of plaintext. The first block is XOR-ed with a vector
known as the "initialization vector" or "IV", which takes the place of the
non-existent block of ciphertext before it. IVs are usually passed along with
the key. The IV does not expand the key-space so much as it impedes
cryptanalysis on the ciphertext.

Most of the primitive operations of AES remain intact, with only the highest
layer of the encryption functions needing to be modified to handle an IV and
behave a little differently from ECB mode. 

This challenge is essentially a modification of challenge 7, and is accordingly
somewhat shorter than one might expect.

## Challenge 11: An ECB/CBC detection oracle
The somewhat undesirable property of ECB as mentioned in Challenge 8 is used
here to distinguish ECB from CBC.

The principle is, unsuprisingly, exactly as in Challenge 18. The oracle is given
a maximally repetitive plaintext of substantial length, and ECB plaintexts will
be detected through repetition in consecutive ciphertext blocks. CBC, due to its
design, will be very unlikely to yield such plaintexts.

## Challenge 12: Byte-at-a-time ECB decryption (Simple)
This is one of the first really interesting attacks in the challenge.

The challenge prompt does, I think, a very good job of explaining the attack. I
will, however, make my own attempt to explain it in what I think is a more
sensible manner. Since you are already looking at a write-up, I am at a little
more liberty to explain the theory behind attack.

### Theory behind the attack
Consider a block of length 16 (as with AES) in ECB mode. Because ECB encrypts
each block independently of the rest of the text, we can consider it in
isolation.

Assume one knows the first 15 bytes, say, `"ABCDEFGHIJKLMNO"`, but not the last
byte, which we will represent here with `?`.

If we have access to an encryption oracle, however, we can quickly figure out
what value of `?` produces the ciphertext we are seeking. (This essentially
cuts the complexity of cryptographic confusion and diffusion baked into each
block of AES)

As there are only 256 possible values for the byte, we have thus substantially
reduced the brute-force complexity by many orders of magnitude by brute-forcing
a byte rather than a 16-byte block all at once.

Now that we have a way to crack a single byte when we know the preceding 15, we
turn our attention to the question of how one would produce such a situation.
For this, we use the encryption oracle given in the challenge.

#### Side note:
For those who would consider this attack a little contrived, I'm not sure I can
satisfy you, but I would assume that this would likely pop up in certain 
situations involving encrypted cookies containing some user-provided data.

## Challenge 13: ECB cut-and-paste


## Challenge 14: Byte-at-a-time ECB decryption (Harder)

## Challenge 15: PKCS#7 padding validation

## Challenge 16: CBC bitflipping attacks