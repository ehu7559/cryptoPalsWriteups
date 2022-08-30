#taken from Set 1, Challenge 7. I was an overachiever uwu

#PKCS#7 Padding as per RFC5652. For ciphertexts with perfect block length,
#simply call this on an empty bytearray.
def pad(data: bytes) -> bytes:
    '''Pad the last block.'''
    output = bytearray(data)
    gap = 16 - (len(data)%16)
    output.extend(bytes([gap for i in range(gap)]))
    return output

#Trims data in accordance with PKCS#7. Does not safeguard against bad data.
def trim_padding(block: bytes) -> bytes:
    datalen = (len(block) - block[-1]) #Works with PKCS7 padding of any type
    return bytes([block[i] for i in range(datalen)])