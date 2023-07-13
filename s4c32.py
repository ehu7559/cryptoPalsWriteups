#Challenge 32: Break HMAC-SHA1 with a slightly less artificial timing leak

#Imports
from random import randint
from time import sleep, time

#HMAC-SHA1 implementation
#TODO: I should do this but it isn't necessarily the point of the challenge.

#Insecure Compare Function
def insecure_comparison(a: bytes, b: bytes):
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
        sleep(0.005) #Apparently my old code was capable of running with tolerance of 5 milliseconds. So I have tightened it!
    return True

#Server
#TODO: I hate web frameworks and this isn't cryptographic. :(
#So I've just used an oracle here. It's so much easier.
#Otherwise you should just grab some web framework boilerplating.

def get_comparison_oracle(reference_data: bytes):
    return lambda x: insecure_comparison(reference_data, x)

#Timing error detection function:
def check_for_time_error(num_bytes, now_time, prev_time):
    '''Checks that the ratio in time comparisons is that expected'''
    #calculate expected difference in time comparisons
    pass

#Attack function
def artificial_timing_attack(oracle):
    attack_buffer = bytearray(20)
    best_buffer = bytearray(20)

    #save timings for error-detection/correction mechanism
    timings = []
    for i in range(20):
        best_time = 0
        for j in range(256):
            print(f"BEST: {best_buffer[:i+1].hex()} TRYING:{attack_buffer.hex()}", end="\r")
            attack_buffer[i] = j
            j_time = run_time_test(oracle, attack_buffer, 100)
            if j_time > best_time:
                j_time_check = run_time_test(oracle, attack_buffer, 100)
                if j_time_check > best_time and j_time_check > run_time_test(oracle, best_buffer, 100):
                    best_buffer[i] = j
                    best_time = j_time
        attack_buffer[i] = best_buffer[i]
    return bytes(attack_buffer)
    
def run_time_test(oracle, data: bytes, num_rounds: int):
    #wouldn't really need this if I wasn't testing this shit on Windows :|
    output = 0
    output -= int(time() * 1000000)
    for i in range(num_rounds):
        oracle(data)
    output += int(time() * 1000000)
    return output

#Main Function
if __name__ == "__main__":
    #Generate random bytes and print for verification
    chall_hash = bytes([randint(0, 255) for i in range(20)])
    print(f"REF:  {chall_hash.hex()}")
    
    #Generate Oracle
    chall_oracle = get_comparison_oracle(chall_hash)

    #Attack the oracle
    recovered_hash = artificial_timing_attack(chall_oracle).hex()
    
    print("\nVERIFYING:")
    if insecure_comparison(recovered_hash, chall_oracle):
        print("--- CHALLENGE STATUS: COMPLETE ---")
    else:
        print("Hashes did not match!")