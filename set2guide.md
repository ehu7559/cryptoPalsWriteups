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
block of AES). We essentially search for what value of `?` yields the ciphertext
we get when we know `ABCDEFGHIJKLMNO?` is in the plaintext.

As there are only 256 possible values for the byte, we have thus substantially
reduced the brute-force complexity by many orders of magnitude by brute-forcing
a byte rather than a 16-byte block all at once.

Now that we have a way to crack a single byte when we know the preceding 15, we
turn our attention to the question of how one would produce such a situation.
For this, we use the encryption oracle given in the challenge. By varying the
length of the data we provide, we can pull exactly 1 unknown byte of the text
we are trying to crack into a block whose first 15 bytes we know (because we
either provided them or previously cracked them). Abusing this feature, we can
brute-force them one at a time. Each byte we crack will be used to crack the
next byte.

### Implementing the attack
For this challenge, I have written a function `generate_oracle()`, which
generates a random key and returns an oracle. The oracle takes a bytes argument
and appends the secret text before encrypting it with a constant but unknown key
determined by the function. This function will give us the target we attack.

#### Determining whether or not it is ECB
The challenge states that we must detect whether or not it is indeed using
ECB encryption. Challenge 8 comes in handy again. We feed the oracle a heavy
diet consisting of the letter `"A"`, which should reveal the repetition of ECB,
if the oracle is indeed using it. 

#### Determining block length
We already know this, but we have to do it anyway. We can gradually add 
incrementally longer inputs until we have two lengths given ciphertexts whose
lengths differ by 1. This allows us to know the minimum difference between two
ciphertexts' length.

#### Feeding it specific inputs
See the `attack_ECB_oracle()` function. For the sake of simplicity, I chose to
use all null bytes for my padding buffers. I pre-computed these ciphertexts for
the sake of speed and efficiency.

#### Brute-forcing/matching!
We will then, for each byte within each block, select the appropriate padding
length. After selecting the block of interest from the corresponding ciphertext,
we can then use the `enum_oracle()` function to find the value of the byte we
are brute-forcing. My solution involves a "sliding window" of sorts, keeping
track of the last 15 known bytes (initially all `0x00`). This allows us to
efficiently brute-force each byte of the ciphertext.

### Running the Attack
The challenge code creates an oracle, feeds it to the attack function, and 
decodes the resulting plaintext guess before printing it as a sign of success.

### Side note on application:
For those who would consider this attack a little contrived, I'm not sure I can
satisfy you, but I would assume that this would likely pop up in certain 
situations involving encrypted cookies containing some user-provided data.

## Challenge 13: ECB cut-and-paste
Again taking advantage of ECB's "stateless-ness", we can use encryption oracles
to craft messages without the key. Due to the block-cipher nature of AES, we
also need to make sure patch together our desired message from whole blocks.

Our desired plaintext is something like this
```
{
    email=...
    uid=1
    role=admin
}
```

With this target plaintext in mind, we can go about crafting messages. First,
consider what blocks we need:

1. Some blocks with an email, uid, and ending in `"role="`.
2. A terminating block beginning with `admin` and ending with `}` plus padding.

We can obtain the second one by feeding a specially crafted email address.

```
"abcdefgadmin\n}\t\t\t\t\t\t\t\t\t"
```

We also need to find an email of the correct length to get the first part.

We can then cut these and paste them together to form our desired JSON.

## Challenge 14: Byte-at-a-time ECB decryption (Harder)
This challenge can be quickly reduced to Challenge 12 through a proxy of sorts
after determining the length of the front-padding.

### Step 1: Determining padding length:
To determine how long the prepending pad is, we first send the oracle an empty
string, which gives us a baseline against which to compare other outputs.

We can then feed the oracle an arbitrary non-empty string to encrypt. Comparing
the two ciphertexts, we can find, to the nearest block (16 bytes), the length of
the prepend pad. 

By then progressively adding bytes to our prepend pad (my code uses null) and
waiting for two blocks to appear identically (using ECB!), corresponding to the
`two_blocks` 32-byte string to determine the exact length of the prepend pad.  

### Step 2: Create a middle-man/proxy
To reduce code duplication, we can create a challenge oracle that finds the
prepend length and pads it to a whole block. Since ECB is, as stated before,
stateless, we are then left with a known (or at least quickly computable) number
of whole blocks followed by what is essentially the oracle from Challenge 12.

We can then create our own lambda which takes the input, prepends the right
number of garbage bytes to separate it from the prepend padding, and then
trims the garbage blocks from the front before returning it.

Those who did well in their college algorithms courses should see what's going
on immediately. (Hooray for reductions!)

### Step 3: Attack this new proxy
We attack the new oracle in exactly the same way we did in Challenge 12. The
attack methods are the same.

### Closing Remark:
This problem didn't so much introduce a new attack as it introduced a small
confounding variable that could be reliably overcome by a programmer with a
thorough understanding of ECB's properties.

## Challenge 15: PKCS#7 padding validation
Honestly, I'm not entirely sure why this was its own challenge rather than a
subproblem of Challenge 17 (which is probably the one thing it's actually used
for. This one is a relatively easy one, especially if you happened to include
padding validation in your implementation of AES in challenge 7.

## Challenge 16: CBC bitflipping attacks
This one is another interesting (if somewhat odd) attack.

The point of this attack is to alter the plaintext through manipulation of the
ciphertext in the absence of the key.

### What mechanism can we use?
The problem actually answers this question for us (which, I suppose, is part of
its educational purpose). We are able to edit the ciphertext through a
bit-flipping attack.

### Some theory/explanations for clarity
The distinguishing feature of CBC mode is that each block of plaintext is XORed
against the previous block of ciphertext before encrypting. During decryption,
the decrypted output would then be XORed against that same ciphertext block to
obtain the plaintext. 

The point is, then, that one can control a bit of obtained plaintext by using
the corresponding bit of the previous block. Flipping a bit in the previous
ciphertext block will thus also flip the corresponding plaintext bit.

This does, however, have the unfortunate side effect of entirely scrambling 
the edited block.

### How can we use it?
Well, given that we can insert an arbitrarily long block into the oracle, and
that we are given back the ciphertext, we can craft a block with any desired
substring in it. Due to the limitations of this attack, our task mercifully
asks us to create a relatively short message.

By feeding it a relatively long but otherwise innocuous message, say,

`"aaaaaaaaaaaaa...aaaa"`

we can then manipulate the block before it (we know the length of the prefix) to
flip the appropriate bits to change it to any desired message.

## Set 2 Closing Remarks:
This set was essentially a crash course of AES block cipher attacks. Honestly,
this was probably the most fun I have had in some time. 
