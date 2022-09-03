#Crack a time-seeded MT19937 pseudo-random number generator

#Imports
from time import time, sleep
from random import randint #Okay I COULD use my MT19937 implementation but humor me here.
from s3c21 import MT19937_stream

def crack_MT19937_seed(start: int, output_words: list, increment = 1, max_depth = -1) -> int:
    output = start
    n = len(output_words) #Precompute and save for speed.
    if max_depth <= 0:
        max_depth = 2**32 - start - 1
    for i in range(max_depth):
        #Generate as many words as is necessary to produce that output
        print(f"Checking Seed: {output}", end="\r")
        crack_gen = MT19937_stream(output)                
        crack_words = [next(crack_gen) for j in range(n)]

        #Check for correctness
        solved = True
        for j in range(n):
            solved = solved and (output_words[j] == crack_words[j])
    
        #If not solved, decrement and attempt to crack again.
        if solved:
            print(f"Cracked Seed: {output} ")
            return output
        
        output += increment
    print("Could not crack seed!")
    return -1

#Challenge code!
if __name__ == "__main__":

    #Get as much out of the way as possible
    chall_sleep_time = randint(40, 1000)
    
    chall_seed_time = int(time())
    crack_start_time = chall_seed_time + chall_sleep_time
    #Get timestamp and seed it!
    chall_gen = MT19937_stream(chall_seed_time)
    print(f"Challenge Seeded Time: {chall_seed_time}")
    chall_words = [next(chall_gen)]
    
    #Sleep
    while chall_sleep_time > 0:
        print(f"{chall_sleep_time} Simulated Seconds Remaining in Delay...",end="\r")
        chall_sleep_time -= 1
        sleep(0.01)
    
    #Crack
    #crack_start_time = int(time() + chall_sleep_time)
    print(f"Beginning Crack at simulated time {crack_start_time}")
    
    cracked_seed = crack_MT19937_seed(crack_start_time, chall_words, -1, crack_start_time)
    print(cracked_seed)
