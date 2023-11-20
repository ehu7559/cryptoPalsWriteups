#Challenge 30: Break an MD4 keyed MAC using length extension

#MD4 digest class
from s4c28 import leftrotate

def encode_uint_little_endian(num : int, length : int) -> bytes:
    output = bytearray()
    for _ in range(length):
        output.append(num % 256)
        num = num >> 8
    return bytes(output)

class MD4:
    
    def __init__(self):
        self.words = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
        self.length = 0
        self.buffer = bytearray()

    def F(x, y, z):
        return ((x & y) | ((~x) & z))

    def G(x, y, z):
        return ((x & y) | (x & z) | (y & z))
    
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
        new_chunk = bytes(self.buffer[0:64])
        self.buffer = self.buffer[64:]
        self.hash_chunk(new_chunk)

        #Exit.
        return
        
    def hash_chunk(self, chunk):
        print(f"hashing chunk {chunk.hex()}")
        #Copy block i in to X
        x = bytearray(chunk)
        #Grab words from hash registers
        A, B, C, D = self.words
        AA, BB, CC, DD = self.words
        
        #ROUND 1:
        for i in range(16):
            match (i % 4):
                case 0: A = MD4.fhelper(A, B, C, D, x[i], 3)
                case 1: D = MD4.fhelper(D, A, B, C, x[i], 7)
                case 2: C = MD4.fhelper(C, D, A, B, x[i], 11)
                case 3: B = MD4.fhelper(B, C, D, A, x[i], 19)
                case _: raise Exception("LMAO Math Broke")
        
        #ROUND 2:
        for i in range(16):
            match (i % 4):
                case 0: A = MD4.ghelper(A, B, C, D, x[(i // 4)], 3)
                case 1: D = MD4.ghelper(D, A, B, C, x[(i // 4) + 4], 5)
                case 2: C = MD4.ghelper(C, D, A, B, x[(i // 4) + 8], 9)
                case 3: B = MD4.ghelper(B, C, D, A, x[(i // 4) + 12], 13)
                case _: raise Exception("LMAO Math Broke")

        #ROUND 3:
        r3indices = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]
        for i in range(16):
            match (i % 4):
                case 0: A = MD4.hhelper(A, B, C, D, x[r3indices[i]], 3)
                case 1: D = MD4.hhelper(D, A, B, C, x[r3indices[i]], 9)
                case 2: C = MD4.hhelper(C, D, A, B, x[r3indices[i]], 11)
                case 3: B = MD4.hhelper(B, C, D, A, x[r3indices[i]], 15)
                case _: raise Exception("LMAO Math Broke")
        
        #UPDATE WORDS
        A = (A + AA) & 0xFFFFFFFF
        B = (B + BB) & 0xFFFFFFFF
        C = (C + CC) & 0xFFFFFFFF
        D = (D + DD) & 0xFFFFFFFF
        self.words = (A, B, C, D)
        return

    def fhelper(a, b, c, d, xval , leftrotation):
        f = MD4.F(b, c, d)
        a = (a + f + xval) & 0xFFFFFFFF
        return leftrotate(a, leftrotation, length=32)
    
    def ghelper(a, b, c, d, xval, leftrotation):
        g = MD4.G(b, c, d)
        a = (a + g + xval + 0x5A827999) & 0xFFFFFFFF
        return leftrotate(a, leftrotation, length=32)
    
    def hhelper(a, b, c, d, xval, leftrotation):
        h = MD4.H(b, c, d)
        a = (a + h + xval + 0x6ED9EBA1) & 0xFFFFFFFF
        return leftrotate(a, leftrotation, length=32)

    def finalize(self):
        self.buffer = MD4.pad_chunk(self.buffer, self.length * 8)
        while len(self.buffer) >= 64:
            self.ingest_chunk()

    def pad_chunk(data, num_bits):
        output = bytearray(data)
        output.append(0x80)
        while len(output) % 64 != 56: output.append(0)
        output.extend(encode_uint_little_endian(num_bits, 8))
        return output

    def get_hash(self):
        output = bytearray()
        A, B, C, D = self.words
        for x in [A, B, C, D]:
            output.extend(encode_uint_little_endian(x, 4))
        return bytes(output)

    def get_hash_str(self):
        return self.get_hash().hex()

    def from_hash_str(hash_string: str):
        #### TODO: NEED TO IMPLEMENT FROM_HASH_STR
        return MD4()

    def hash(data: bytes):
        digest = MD4()
        digest.ingest(data)
        digest.finalize()
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
    print("This is an implementation challenge. There is no expected output.")
    print(f"\n{MD4.hash('The saddest aspect of life right now is that science gathers knowledge faster than society gathers wisdom.'.encode())}\n")
    print("--- CHALLENGE STATUS: IN PROGRESS ---")