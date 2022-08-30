#Break an MD4 keyed MAC using length extension

#MD4 digest class
from s4c28 import encode_uint_big_endian

class MD4:
    
    def __init__(self):
        self.words = [0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210]
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

#Oracle
def get_oracle(key):
    return lambda m, h : MD4.validate_keyed_MAC(key, m, h)

#Attack function in same style
def attack(oracle, message, hash, tail):
    pass

#Run Challenge code
if __name__ == "__main__":
    pass