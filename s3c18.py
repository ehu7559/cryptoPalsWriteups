#Challenge 18

#Imports

#Keystream oracle function
def aes_ctr_keystream(aes_key, nonce):
    counter = 0
    while True:
        #Generate keystream block
        output = bytes()
        #Compute with the 
        for i in range(16):
            yield output[i]
        counter += 1

#CTR Mode Implementation

#Challenge Code
if __name__ == "__main__":
    print("--- CHALLENGE STATUS: INCOMPLETE ---")