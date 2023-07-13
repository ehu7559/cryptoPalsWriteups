#Challenge 31: Implement and break HMAC-SHA1 with an artificial timing leak

#Imports
from random import randint
from time import process_time_ns, sleep

GLOBAL_TIME = 0
#HMAC-SHA1 implementation
#TODO: I should do this but it isn't necessarily the point of the challenge.

#Insecure Compare Function
def insecure_comparison(a: bytes, b: bytes):
    global GLOBAL_TIME
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
        sleep(0.05)
        GLOBAL_TIME += 5
    return True


#Server
#TODO: I hate web frameworks and this isn't cryptographic. :|
#So I've just used an oracle here. It's so much easier.
#Otherwise you should just grab some web framework boilerplating.

def get_comparison_oracle(reference_data: bytes):
    return lambda x: insecure_comparison(reference_data, x)

#Attack function
def artificial_timing_attack(oracle):
    attack_buffer = bytearray(20)
    for i in range(20):
        best_j = 0
        best_time = 0
        for j in range(256):
            attack_buffer[i] = j
            j_time = get_median_time(oracle, attack_buffer, 100)
            #print(attack_buffer.hex(), end="\r")
            if j_time > best_time:
                best_j = j
                best_time = j_time
                print(attack_buffer.hex(), end="\r")
        attack_buffer[i] = best_j
    return bytes(attack_buffer)

def get_median_time(oracle, data, set_size):
    global GLOBAL_TIME
    before = process_time_ns()
    for i in range(set_size):
        oracle(data)
    after = process_time_ns()
    return after - before

#Main Function
if __name__ == "__main__":
    #Generate random bytes and print for verification
    chall_hash = bytes([randint(0, 255) for i in range(20)])
    print(chall_hash.hex())

    #Generate Oracle
    chall_oracle = get_comparison_oracle(chall_hash)

    #Attack the oracle
    recovered_hash = artificial_timing_attack(chall_oracle).hex()
    
    print("\nVERIFYING...")
    if insecure_comparison(recovered_hash, chall_hash.hex()):
        print("--- CHALLENGE STATUS: COMPLETE ---")
    else:
        print("Hashes did not match!")