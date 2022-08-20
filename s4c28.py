#SHA-1 Keyed MAC

class SHA1Digest:

    def __init__(self):
        '''Initializes a SHA-1 hash object with the default values'''
        self.h = [0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0]
        self.length = 0
        self.buffer = bytearray()
    
    def ingest(self, data : bytes):
        '''Takes in data, increments length, and hashes complete blocks'''
        self.length += len(data)
        self.buffer.extend(data)
        while len(self.buffer) > 64:
            self.ingest_chunk()
        return

    def ingest_chunk(self):
        '''Hashes and updates for a single 512-bit chunk of data'''

        #Error message
        if len(self.buffer) < 64:
            raise Exception("Insufficient Data To Ingest Block" + str(self.buffer))

        #Grab new chunk and hash it.
        new_chunk = bytes([self.buffer.pop(0) for i in range(64)]) 
        chunk_hash = self.hash_chunk(new_chunk)

        #Update the inner hash value
        self.h = [(self.h[i] + chunk_hash[i]) % (4294967296) for i in range(5)]
        return

    def hash_chunk(self, chunk):
        '''Takes in a chunk and hashes it'''
        if len(chunk) != 64:
            raise Exception("ERROR: Tried to hash hunk of length " + len(chunk) + " bytes instead of 64")
        
        #Message Schedule
        w = [decode_uint_big_endian(chunk[4 * i: 4 * (i + 1)]) for i in range(16)]

        for i in range(16, 80):
            new_val = leftrotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1, 32)
            w.append(new_val)

        #Initialize hash value for this chunk
        a = int(self.h[0])
        b = int(self.h[1])
        c = int(self.h[2])
        d = int(self.h[3])
        e = int(self.h[4])

        #Initialize temp
        for i in range(80):
            F_ARR = [((b & c) | ((~b) & d)), (b ^ c ^ d), ((b & c) | (b & d) | (c & d)), (b ^ c ^ d)]
            K_ARR = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]
            f = F_ARR[i//20]
            k = K_ARR[i//20]

            temp = (leftrotate(a, 5) + f + e + k + w[i]) % (4294967296)
            e, d, c, b, a = (d, c, leftrotate(b, 30), a, temp)

        return [a, b, c, d, e]

    #Need to check length
    def finalize(self) -> None:
        '''Pads and ingests any remaining'''
        self.buffer.append(0x80)
        while len(self.buffer) % 64 != 56:
            self.buffer.append(0)
        self.buffer.extend(encode_uint_big_endian(self.length * 8, 8))
        while len(self.buffer) > 0:
            self.ingest_chunk()
        return
    
    #Working as intended
    def get_hash(self):
        output = bytearray()
        for i in range(5):
            output.extend(encode_uint_big_endian(self.h[i], 4))
        return bytes(output)

    #Working as intended.
    def get_hash_str(self):
        return self.get_hash().hex()

    def from_hash_str(hash_str):
        new_digest = SHA1Digest()
        new_digest.h = [decode_uint_big_endian(bytes.fromhex(hash_str)[4 * i : 4 * (i + 1)]) for i in range(5)]
        return new_digest

    def set_length(self, length: int):
        self.length = length

def sha1_hash(data : bytes):
    digest = SHA1Digest()
    digest.ingest(data)
    digest.finalize()
    return digest.get_hash_str()

def hash_file(filename):
    digest = SHA1Digest()
    with open(filename, "rb") as in_file:
        quarter_chunk = in_file.read(16)
        while quarter_chunk:
            digest.ingest(quarter_chunk)
            quarter_chunk = in_file.read(16)
    digest.finalize()
    return digest.get_hash_str()

#Working as intended
def encode_uint_big_endian(num, length):
    output = bytearray()
    curr = int(num)
    for i in range(length):
        output.insert(0, curr % 256)
        curr = curr // 256
    return bytes(output)

#Working as intended.
def decode_uint_big_endian(data):
    output = 0
    curr = bytearray(data)
    place = 1
    while len(curr) > 0:
        output += (curr.pop() * place)
        place *= 256
    return output

def leftrotate(num, shift, length=32):
    return (num * (2 ** shift) + (num // (2**(length - shift)))) % (2**length)

def SHA1_keyed_MAC(key, message):
    pair = bytearray(key)
    pair.extend(message)
    return (bytes(message), sha1_hash(bytes(pair)))

if __name__ == "__main__":
    print("emptyfile.txt : " + hash_file("emptyfile.txt"))
    print("8.txt : " + hash_file("8.txt"))
    print("set1guide.md : " + hash_file("set1guide.md"))
