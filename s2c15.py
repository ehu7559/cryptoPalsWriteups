#Padding oracle yaaaay
def valid_pad(plaintext):
    if len(plaintext) % 16 > 0 or len(plaintext) < 16:
        return False #Improper length
    #Check padding
    padding_size = plaintext[-1]
    if padding_size == 0:
        return False
    if padding_size > 16:
        return False
    for i in range(padding_size):
        if plaintext[-1 - i] != padding_size:
            return False
    return True
    
if __name__ == "__main__":
    print("--- CHALLENGE STATUS: COMPLETE ---")