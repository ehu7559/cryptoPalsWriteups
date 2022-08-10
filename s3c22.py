#Crack a time-seeded MT19937 pseudo-random number generator

#Imports
from time import time, sleep
from random import randint #Okay I COULD use my MT19937 implementation but humor me here.
from s3c21 import MT19937_stream

def crack_time_MT19937(latest, output_words, decrement = -1, max_depth = -1):
    output = latest
    n = len(output_words) #Precompute and save for speed.
    if max_depth <= 0:
        max_depth = latest
    for i in range(max_depth):
        #Generate as many words as is necessary to produce that output
        crack_gen = MT19937_stream(output)                
        crack_words = [next(crack_gen) for j in range(n)]

        #Check for correctness
        solved = True
        for j in range(n):
            solved = solved and (output_words[j] == crack_words[j])
    
        #If not solved, decrement and attempt to crack again.
        if solved:
            return output
        
        output += decrement
    return -1

#Quality of Life feature: a timer i shamelessly stole from a StackOverFlow post.
def countdown(t):
    
    while t:
        mins, secs = divmod(t, 60)
        timer = '{:02d}:{:02d}'.format(mins, secs)
        print(timer, end="\r")
        time.sleep(1)
        t -= 1


#Challenge code!
if __name__ == "__main__":

    #Get as much out of the way as possible
    chall_sleep_time = randint(40, 1000)
    chall_seed_time = int(time())
    #Get timestamp and seed it!
    chall_gen = MT19937_stream(chall_seed_time)
    print(f"Challenge Seeded Time: {chall_seed_time}")
    chall_words = [next(chall_gen)]
    
    #Sleep
    print(f"Wait time: {chall_sleep_time} seconds")
    sleep(chall_sleep_time)

    #Crack
    crack_start_time = int(time())
    print(f"Beginning Crack at time {crack_start_time}")
    
    cracked_seed = crack_time_MT19937(crack_start_time, chall_words, -1, 1000)
    print(cracked_seed)