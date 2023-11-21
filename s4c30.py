#Challenge 30: Break an MD4 keyed MAC using length extension

#MD4 digest class
from s4c28 import leftrotate
from random import randint


def parse_uint_little_endian(buf : bytes) -> int:
    output = 0
    buf = bytearray(buf)
    while buf:
        output = output << 8
        output += (buf.pop() & 0xFF)
    return output

def encode_uint_little_endian(num : int, length : int) -> bytes:
    output = bytearray()
    for _ in range(length):
        output.append(num & 0xFF)
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
        
        #Word-ify the chunks
        x = [parse_uint_little_endian(chunk[4 * i : 4 * (i + 1)]) for i in range(16)]

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
        assert len(hash_string) == 32
        hash_bytes = bytes.fromhex(hash_string)
        words = [parse_uint_little_endian(hash_bytes[4 * i : 4 * (i + 1)]) for i in range(4)]
        output = MD4()
        output.words = words
        assert(len(output.words) == 4)
        return output

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

def testmd4():
    '''runs test cases defined in RFC 1320'''
    test0 = checkmd4("","31d6cfe0d16ae931b73c59d7e0c089c0")
    test1 = checkmd4("a","bde52cb31de33e46245e05fbdbd6fb24")
    test2 = checkmd4("abc","a448017aaf21d8525fc10ae87aa6729d")
    test3 = checkmd4("message digest", "d9130a8164549fe818874806e1c7014b")
    test4 = checkmd4("abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9")
    test5 = checkmd4("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4")
    test6 = checkmd4("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536")
    return all([test0,test1,test2,test3,test4,test5,test6])

def checkmd4(string : str, reference:str):
    stringhash = MD4.hash(string.encode())
    return stringhash == reference

def testmd4_fromhashstr(hashstring):
    assert len(hashstring) == 32
    fromhash = MD4.from_hash_str(hashstring)
    print(fromhash.get_hash_str())

def attack_with_known_saltlength(hashstring : str, message : bytes, payload : bytes, saltlen:int):
    
    digest = MD4.from_hash_str(hashstring)
    print(digest.get_hash_str())
    origlen = len(message) + saltlen
    message = bytearray(message)
    message = MD4.pad_chunk(message, origlen * 8)[saltlen:]
    digest.set_length(len(message) + saltlen)
    message.extend(payload)
    digest.ingest(payload)
    digest.finalize()
    print(digest.get_hash_str())
    print(MD4.hash(message))
    
#Run Challenge code
if __name__ == "__main__":
    print(f"MD4 Test (RFC1320): {'SATISFACTORY' if testmd4() else 'FAILURE'}")

    #Select Message
    chall_message = "This is a challenge message. Nothing up my sleeves at all.".encode()
    chall_payload = "pwned".encode()
    chall_start_hash = MD4.hash(chall_message)
    print(chall_start_hash)
    attack_with_known_saltlength(chall_start_hash, chall_message, chall_payload, 0)
    #Select
