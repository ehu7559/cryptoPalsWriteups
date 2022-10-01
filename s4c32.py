#Break HMAC-SHA1 with a slightly less artificial timing leak

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
        sleep(0.001) #Apparently my old code was capable of running with tolerance of 5 milliseconds. So I have tightened it!
    return True


#Server
#TODO: I hate web frameworks and this isn't cryptographic. :(
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
            j_time = run_time_test(oracle, attack_buffer, 10)
            if j_time > best_time:
                best_j = j
                best_time = j_time
        attack_buffer[i] = best_j
        print(f"Progress: {(i + 1) * 5}%", end="\r") #One must be careful not to print too often for fear of slowing down the computer!
    return bytes(attack_buffer)
    

def run_time_test(oracle, data: bytes, num_rounds: int):
    #wouldn't really need this if I wasn't testing this shit on Windows :|
    output = 0
    output -= int(time() * 100000)
    for i in range(num_rounds):
        oracle(data)
    output += int(time() * 100000)
    return output

#Main Function
if __name__ == "__main__":
    #Generate random bytes and print for verification
    chall_hash = bytes([randint(0, 255) for i in range(20)])
    print(chall_hash.hex())
    
    #Generate Oracle
    chall_oracle = get_comparison_oracle(chall_hash)

    #Attack the oracle
    recovered_hash = artificial_timing_attack(chall_oracle).hex()
    
    print("\nVERIFYING:")
    if insecure_comparison(recovered_hash, chall_oracle):
        print("--- CHALLENGE STATUS: COMPLETE ---")
    else:
        print("Hashes did not match!")