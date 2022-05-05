
#taken from Set 1, Challenge 7. I was an overachiever uwu

#PKCS7 Padding as per RFC5652. For ciphertexts with perfect block length,
#simply call this on an empty bytearray.
def pad(data):
    '''Pad the last block.'''
    output = bytearray(data)
    gap = 16 - (len(data)%16)
    output.extend(bytes([gap for i in range(gap)]))
    return output

def trim_padding(block):
    datalen = (len(block) - block[-1]) #Works with PKCS7 padding of any type
    return bytes([block[i] for i in range(datalen)])