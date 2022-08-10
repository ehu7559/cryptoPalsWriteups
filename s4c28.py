#SHA-1 Keyed MAC
from s1c2 import buf_xor
#SHA1 Function:




class SHA1:
    def hash(data: bytes) -> bytes:
        h0 = bytes.fromhex("67452301")
        h1 = bytes.fromhex("EFCDAB89")
        h2 = bytes.fromhex("98BADCFE")
        h3 = bytes.fromhex("10325476")
        h4 = bytes.fromhex("C3D2E1F0")

        ml = len(data) * 8

        #pre-processing
        data = bytearray(data)
        data.append(128)
        pass    

    def digest_block(data: bytes, init_hash = bytes.fromhex("67452301EFCDAB8998BADCFE1032F476")) -> bytes:
        '''digests a 512-bit block'''
        for i in range(80):
            pass