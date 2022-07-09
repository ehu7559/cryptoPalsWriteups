#Implement the Mersenne Twister

class MT_UTIL:

    def xor_bit(a,b):
        return str(int(a) ^ int(b))

    def bitstring_xor(a,b):
        output = ""
        for i in range(len(a)):
            output += MT_UTIL.xor_bit(a[i],b[i])
        return output

class Mersenne_Twister:
    '''
    M19937 PARAMETERS:
    (w, n, m, r) = (32, 624, 397, 31)
    a = 0x9908B0DF
    (u, d) = (11, 0xFFFFFFFF) <-- Wikipedia indicates that "32-bit implementations of the Mersenne Twister generally have d = FFFFFFFF_16. As a result, the d is occasionally omitted from the algorithm description, since the bitwise AND with d in that case has no effect. 
    (s, b) = (7, 0x9D2C5680)
    (t, c) = (15, 0xEFC60000)
    l = 18
    '''

    MT19937_PARAMS = [(32, 624, 397, 31), bytes([])]

    #Constructor
    def __init__(self, seed, parameters=None):
        
        self.seed = seed
        self.params = parameters

        #default to MT19937
        if self.params == None:
            self.params = Mersenne_Twister.MT19937_PARAMS
        
        #Set actual constants/values
        self.w, self.n, self.m, self.r = self.params[0]
        self.a = self.params[1]
        self.u, self.d = self.params[2]
        self.s, self.b = self.params[3]
        self.t, self.c = self.params[4]
        self.l = self.params[5]

        #Initialize state buffer
        self.initialize_state()

    #Initialization Function
    def initialize_state(self):
        #Use seed to initialize the state buffer
        pass


    
    #Outputting function
