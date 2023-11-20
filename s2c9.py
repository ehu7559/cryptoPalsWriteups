#Taken from Set 1, Challenge 7.

#PKCS#7 Padding as per RFC5652. For ciphertexts with perfect block length,
#simply call this on an empty bytearray.
def pad(data: bytes) -> bytes:
    '''Pad the last block.'''
    output = bytearray(data)
    gap = 16 - (len(data) & 0xF)
    output.extend(bytes([gap for _ in range(gap)]))
    return output

#Trims data in accordance with PKCS#7. Does not safeguard against bad data.
def trim_padding(block: bytes) -> bytes:
    if len(block) == 0:
        raise Exception("Trying to trim an empty AES ciphertext!")
    if len(block) & 0xF:
        raise Exception(f"Expected AES ciphertext with length multiple of 16\nGot ciphertext with length {len(block)} instead!")
    padding_length = block[-1]
    if padding_length == 0 or padding_length > 16:
        raise Exception(f"Expected Padding Length in interval [1,16], found {padding_length} instead!")
    for i in range(padding_length):
        #The standards for PKCS#7 also seem to allow null bytes after the length byte.
        if block[-1] != padding_length and (i != 0 and block[-1] != 0):
            raise Exception("Padding Not Compliant with PKCS#7")
        block = block[:-1]
    return bytes(block)

if __name__ == "__main__":
    print("--- CHALLENGE COMPLETE ---")