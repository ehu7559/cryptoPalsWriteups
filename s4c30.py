#Break an MD4 keyed MAC using length extension

#MD4 digest class
from s4c28 import encode_uint_big_endian
from s1c2 import buf_xor


class MD4:
    
    def __init__(self):
        self.words = (0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210)
        self.length = 0
        self.buffer = bytearray()

    def F(x, y, z):
        return (x & y) | (~x & z)

    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)
    
    def H(x, y, z):
        return x ^ y ^ z
    
    def ingest(self, data: bytes):
        self.length += len(data)
        self.buffer.extend(data)
        while len(self.buffer) >= 64:
            self.ingest_chunk()

    def ingest_chunk(self):
        #Error message
        if len(self.buffer) < 64:
            raise Exception("Insufficient Data To Ingest Block" + str(self.buffer))

        #Grab new chunk and hash it.
        new_chunk = bytes([self.buffer.pop(0) for i in range(64)]) 
        chunk_hash = self.hash_chunk(new_chunk)
        
        # Update hash state

        #Return.
        
    def hash_chunk(self, chunk):
        #TODO: Finish implementing MD4
        #Copy block i in to X
        x = bytearray(chunk)
        #Grab words from hash registers
        A, B, C, D = self.words

        #ROUND 1:
        #Let [abcd k s] denote the operation:
        #       a = (a + F(b c d) + X[k] <<< s)
        #Do the following 16 operations
        '''
        [ABCD  0  3]  [DABC  1  7]  [CDAB  2 11]  [BCDA  3 19]
        [ABCD  4  3]  [DABC  5  7]  [CDAB  6 11]  [BCDA  7 19]
        [ABCD  8  3]  [DABC  9  7]  [CDAB 10 11]  [BCDA 11 19]
        [ABCD 12  3]  [DABC 13  7]  [CDAB 14 11]  [BCDA 15 19]
        '''

        pass

    def finalize(self):
        self.buffer = MD4.pad_chunk(self.buffer, self.length * 8)
        while len(self.buffer) >= 64:
            self.ingest_chunk()

    def pad_chunk(data, num_bits):
        output = bytearray(data)
        while len(output) % 64 != 56:
            output.append(0)
        output.extend(encode_uint_big_endian(num_bits, 8))
        return output

    def get_hash(self):
        output = bytearray()
        for i in range(4):
            output.extend(self.words[i])
        return bytes(output)

    def get_hash_str(self):
        return self.get_hash().hex()

    def from_hash_str(hash_string: str):
        #### TODO: NEED TO IMPLEMENT FROM_HASH_STR
        return MD4()

    def hash(data: bytes):
        digest = MD4()
        digest.ingest(data)
        return digest.get_hash_str()

    def keyed_MAC(key, data):
        digest = MD4()
        digest.ingest(key)
        digest.ingest(data)
        return (data, digest.get_hash_str())

    def validate_keyed_MAC(key, data, hash_str):
        _, check_hash = MD4.keyed_MAC(key, data)
        return check_hash == hash_str

    def set_length(self, length: int):
        self.length = length
    
#Oracle
def get_oracle(key):
    return lambda m, h : MD4.validate_keyed_MAC(key, m, h)

#Attack function in same style
def attack(oracle, message : bytes, hash_string : str, message_tail : bytes, max_depth = 65535):
    #Attack Loop for each key length possibility  (in bytes)
    for key_length in range(max_depth):
        #Generate digest object
        digest = MD4.from_hash_str(hash_string)
        
        #Generate Payload
        payload = bytearray(key_length) #0s in place of key
        payload.extend(message) #Append message to the placeholder key

        #Compute and encode the pair's length
        pair_length_bytes = len(payload)
        
        digested = MD4.pad_chunk(payload , pair_length_bytes * 8)
        digest.set_length(len(digested))

        #Craft forged message (Remove key prefix add tail)
        forged_message = bytearray(digested[key_length:]) #Forged = message + glue
        forged_message.extend(message_tail)

        #Ingest the message tail and finalize it.
        digest.ingest(message_tail)
        digest.finalize()

        #Get hash
        new_hash = digest.get_hash_str()
        
        if oracle(forged_message, new_hash):
            return (bytes(forged_message), new_hash)

    #Return none if not possible.
    return None 

#Run Challenge code
if __name__ == "__main__":
    pass