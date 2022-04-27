#AES-ECB Implementation
'''
My thanks to Drs. Nathan Manning and Jonathan Katz 

This was done by hand for educational reasons. This is by no means an efficient
implementation (although efforts have been made to make this as streamlined as
possible), but it is a very understandable one. One can improve this by first
changing to a compiled language like C and then modified to take advantage of
any hardware shortcuts that might be available.

If you are the UMD CS graduate school admissions, please take my work into
account when doing my admissions decision, as I put no small amount of effort 
into this little project of mine.
'''

#Imports
import base64

#Constants and lookup tables
ROUNDS = {128 : 10, 192 : 12, 256 : 14}
BLOCK_SIZE_BITS = 128
BLOCK_SIZE_BYTES = BLOCK_SIZE_BITS//8
NUM_ROUNDS = ROUNDS[BLOCK_SIZE_BITS]

#Pre-computed tables to save time and lower grief of debugging
SB_TABLE = bytes([99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22])
INV_SB_TABLE = bytes([82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203, 84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37, 114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146, 108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132, 144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6, 208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107, 58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115, 150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110, 71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27, 252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244, 31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, 96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125])
SR_TABLE = bytes([0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11])
INV_SR_TABLE = bytes([0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3])
ROUND_CONSTANTS = bytes([0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36])  #PRELOADED CONSTANTS FTW

#FUNCTIONS FOR AES
#Sub bytes
def sub_bytes(block):
    output = bytearray(16)
    for i in range(16):
        output[i] = SB_TABLE[block[i]]
    return bytes(output)

#Shift rows
def shift_rows(block):
    output = bytearray(16)
    for i in range(16):
        output[i] = block[SR_TABLE[i]]
    return bytes(output)

#HELPER METHOD TO MULTIPLY FOR MIX_COLUMNS
def multiply(b,a):
    if b == 1:
        return a
    tmp = (a<<1) & 0xff
    if b == 2:
        return tmp if a < 128 else tmp^0x1b
    if b == 3:
        return tmp^a if a < 128 else (tmp^0x1b)^a

#Mix Columns
def mix_columns(block):
    #initialize constants
    output = bytearray(16)
    mar = [2, 1, 1, 3, 3, 2, 1, 1, 1, 3, 2, 1, 1, 1, 3, 2]

    #mix the columns
    for i in range(16):
        row = i % 4
        col = i // 4
        folder = bytearray(4)
        for j in range(4):
            folder[j] = multiply(mar[j * 4 + row], block[col * 4 + j])
        output[i] = folder[0] ^ folder[1] ^ folder[2] ^ folder[3]

    return bytes(output)

#Add Round Key
def add_round_key(block, round_key):
    output = bytearray(16)
    for i in range(16):
        output[i] = block[i] ^ round_key[i]
    return bytes(output)

#Inverse sub bytes
def inv_sub_bytes(block):
    output = bytearray(16)
    for i in range(16):
        output[i] = block[INV_SB_TABLE[i]]
    return bytes(output)

#Inverse shift rows
def inv_shift_rows(block):
    output = bytearray(16)
    for i in range(16):
        output[i] = block[INV_SR_TABLE[i]]
    return bytes(output)

#Inverse mix columns
def inv_mix_columns(block):
    '''Inverse of MixColumns, takes advantage of math'''
    return mix_columns(mix_columns(mix_columns(block)))
 
#Invert add round key
def inv_add_round_key(block, round_key):
    return add_round_key(block, round_key)

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

#Round Key Extension Function
def run_key_schedule(keybytes):
    #initialize key schedule column
    key_columns = [keybytes[0:4], keybytes[4:8], keybytes[8:12], keybytes[12:16]]

    #Generate rows for keys)
    for i in range(4, 4 * (ROUNDS[BLOCK_SIZE_BITS]) + 4):
        #Load the base value for the column
        new_column = bytearray(key_columns[i-4])
        prev_column = bytearray(key_columns[i-1])

        #Compute new column as per Lawrence book
        if i%4 == 0:
            #Compute T(W(i-1)) 
            shifted_column = bytearray([prev_column[1], prev_column[2], prev_column[3], prev_column[0]])
            subbed_column = bytearray([SB_TABLE[shifted_column[0]], SB_TABLE[shifted_column[1]], SB_TABLE[shifted_column[2]], SB_TABLE[shifted_column[3]]])
            t_column = bytearray([subbed_column[0] ^ ROUND_CONSTANTS[(i-4)//4], subbed_column[1], subbed_column[2], subbed_column[3]])
            prev_column = bytearray(t_column)
        for j in range(4):
            new_column[j] = new_column[j] ^ prev_column[j]
        
        #Append 
        key_columns.append(bytes(new_column))  
    return key_columns

def get_round_keys(initial_key):
    #Generate the Rijndael Key Schedule and then chunkify it.
    key_table = run_key_schedule(initial_key)
    round_key_list = []
    for i in range(ROUNDS[BLOCK_SIZE_BITS] + 1):
        arkey = bytearray()
        for j in range(4):
            arkey.extend(key_table[4*i + j])
        round_key_list.append(bytes(arkey))
    return round_key_list

#Block Encryption Function (Can be used for any mode such as ECB, CBC, or CTR)
def encrypt_block_128(block, aes_key):
    output = bytearray(block)
    
    #Get the round keys
    round_keys = get_round_keys(aes_key)
    
    #Do process as specified by Lawrence
    output = add_round_key(output, round_keys[0])
    
    #Rounds of Rijndael
    for i in range(1,10):
        output = sub_bytes(output)
        output = shift_rows(output)
        output = mix_columns(output)
        output = add_round_key(output,round_keys[i])
    
    #Final round (with canonical missing mix_columns operation.
    output = sub_bytes(output)
    output = shift_rows(output)
    output = add_round_key(output, round_keys[10])
    
    return bytes(output)

#Main Encryption Function for ECB128
def encrypt_AES_ECB_128(data, aes_key):

    #chunkify the data
    blocks = []
    working = bytearray()
    for i in data:
        working.append(i)
        if len(working) == 16:
            blocks.append(bytes(working))
            working = bytearray()
    blocks.append(pad_block(working))
    
    #encrypt one by one
    for i in range(len(blocks)):
        blocks[i] = encrypt_block_128(blocks[i], aes_key)
    
    #RETURN DATA
    output = bytearray()
    for ab in blocks:
        output.extends(ab)
    
    return bytes(output)
    
#Main Decryption Functions
def decrypt_block_128(data, aes_key):
    
    output = bytearray(block)
    
    #Get the round keys
    round_keys = get_round_keys(aes_key)
    
    #Do process as specified by Lawrence
    output = add_round_key(output, round_keys[10])
    
    #Rounds of Rijndael
    for i in range(9, 0, -1): #Produces 9 rounds of AES with reversed key order.
        output = inv_sub_bytes(output)
        output = inv_shift_rows(output)
        output = inv_mix_columns(output)
        output = inv_add_round_key(output,round_keys[i])
    
    #Final round (with canonical missing mix_columns operation.
    output = inv_sub_bytes(output)
    output = inv_shift_rows(output)
    output = inv_add_round_key(output, round_keys[0])
    
    return bytes(output)
    
def decrypt_AES_ECB_128(data, aes_key):

    #BLOCKS: Much more efficient thanks to known block parity
    num_blocks = len(data)//16
    blocks = []
    for i in range(num_blocks):
        blocks.append(bytes(data[16 * i: 16 * (i + 1)]))
    
    #Decrypt blocks individually
    for i in range(len(blocks)):
        blocks[i] = encrypt_block_128(blocks[i], aes_key)
        
    #Trim the padding (yaaaay)
    #blocks[-1] = trim_padding(blocks[-1])
        
    #RETURN DATA
    output = bytearray()
    for ab in blocks:
        output.extend(ab)
    
    return bytes(output)

def retrieve_data(filename):
    '''(string) -> bytes'''
    f = open(filename, "r")
    ls = f.readlines()
    f.close()
    sixtyfour = ""
    for l in ls:
        sixtyfour += l.strip()
    return bytes(base64.b64decode(sixtyfour))

#Main Function:
def challenge():
    ciphertext = retrieve_data("7.txt")
    KEY = bytes("YELLOW SUBMARINE","ascii")
    plain_bytes = decrypt_AES_ECB_128(ciphertext, KEY)
    print(plain_bytes)

DOING_CHALLENGE = True

if __name__ == "__main__":
    if DOING_CHALLENGE:
        challenge()
