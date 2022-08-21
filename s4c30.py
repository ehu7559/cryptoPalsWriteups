#Break an MD4 keyed MAC using length extension

#MD4 digest class
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
        while len(self.buffer) > 64:
            self.ingest_chunk()

    def ingest_chunk(self):
        if len(self.buffer) < 64:
            raise Exception("Insufficient Bytes To Ingest MD4")
        pass

    def finalize(self):
        self.buffer.append(0)
        while len(self.buffer) % 64 != 56:
            self.buffer.append(0)
        pass

    def get_hash(self):
        pass

    def get_hash_str(self):
        pass

    def hash(data: bytes):
        pass

    def keyed_MAC(key, data):
        pass

    def validate_keyed_MAC(key, data, hash_str):
        pass

#Oracle
def get_oracle(key):
    return lambda m, h : MD4.validate_keyed_MAC(key, m, h)

#Attack function in same style
def attack(oracle, message, hash, tail):
    pass

#Run Challenge code
if __name__ == "__main__":
    pass