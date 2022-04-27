
#taken from Set 1, Challenge 7. I was an overachiever uwu

#PKCS7 Padding as per RFC5652. For ciphertexts with perfect block length,
#simply call this on an empty bytearray.
def pad_block(data):
    '''Pad the last block.'''
    output = bytearray(data)
    gap = 16 - len(data)
    for i in range(gap):
        output.append(gap) #Add padding bytes.
    return output

def trim_padding(data):
    output = bytearray(16 - data[-1]) #Works with PKCS7 padding of any type
    for i in range(len(output)):
        output[i] = data[i] #Copies data over
    return bytes(output) #Casts and returns the value