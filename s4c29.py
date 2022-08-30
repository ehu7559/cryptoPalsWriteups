#Break a SHA-1 keyed MAC using length extension
from s4c28 import SHA1, encode_uint_big_endian
from random import randint

#Oracle generator
def get_oracle(key):
    return lambda m, h : SHA1.validate_keyed_MAC(key, m, h)

#Attack Function
def attack(oracle, message : bytes, hash_string : str, message_tail : bytes, max_depth = 65535):
    
    #Attack Loop for each key length possibility  (in bytes)
    for key_length in range(max_depth):
        #Generate digest object
        digest = SHA1.from_hash_str(hash_string)
        
        #Generate Payload
        payload = bytearray(key_length) #0s in place of key
        payload.extend(message) #Append message to the placeholder key

        #Compute and encode the pair's length
        pair_length_bytes = len(payload)
        
        digested = SHA1.pad_chunk(payload , pair_length_bytes * 8)
        digest.set_length(len(digested))

        #Craft forged message (Remove key prefix add tail)
        forged_message = bytearray(digested[key_length:]) #Forged = message + glue
        forged_message.extend(message_tail)

        #Ingest the message tail and finalize it.
        digest.ingest(message_tail)
        digest.finalize()

        #Get hash
        new_hash = digest.get_hash_str()
        
        if oracle(forged_message, new_hash):
            return (bytes(forged_message), new_hash)

    #Return none if not possible.
    return None 

if __name__ == "__main__":
    #Generate Key
    oracle_key_size = randint(16, 256)
    oracle_key = bytes(randint(0,255) for i in range(oracle_key_size))

    print(f"Oracle Key Size: {oracle_key_size}")
    #Generate Oracle
    chall_oracle = get_oracle(oracle_key)

    #Select Message
    chall_message_len = randint(256, 512)
    chall_message = "This is a challenge message. Nothing up my sleeves at all.".encode("utf-8")
    chall_message, chall_init_hash = SHA1.keyed_MAC(oracle_key, chall_message)
    print("Message: " + str(chall_message))
    print("Hash: " + chall_init_hash)

    forged_message, forged_hash = attack(chall_oracle, chall_message, chall_init_hash, "___you'vebeenpwned".encode("ascii"))

    print("Forged Message: " + str(forged_message))
    print("Forged Hash: " + forged_hash)
    check_msg, check_hash = SHA1.keyed_MAC(oracle_key, forged_message)
    print("Check Hash:  " + check_hash)

    if forged_hash == check_hash:
        print("--- CHALLENGE STATUS: COMPLETE ---")