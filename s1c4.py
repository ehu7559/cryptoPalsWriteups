from s1c3 import decrypt, score_text

MIN_SCORE = 1200

#Simple summation method. should work for texts of the same length 


#Challenge Data retrieval
def retrieve_data() -> list[str]:
    with open('4.txt',"r") as f:
        return f.readlines()

#Challenge code
if __name__ == "__main__":
    for l in retrieve_data():
        
    print("--- CHALLENGE STATUS: COMPLETE ---")
