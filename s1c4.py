from s1c3 import guess_single_byte_xor_key, score_english_buffer, decrypt_single_byte_xor, safe_decode_string_from_bytes

MIN_SCORE = 48

#Challenge Data retrieval
def get_chall_lines() -> list[str]:
    with open('4.txt',"r") as f:
        return f.readlines()

#Challenge code
if __name__ == "__main__":
    for l in get_chall_lines():
        buf = bytes.fromhex(l)
        key_guess = guess_single_byte_xor_key(buf)
        plain_buf = decrypt_single_byte_xor(buf, key_guess)
        key_score = score_english_buffer(plain_buf)
        if key_score > MIN_SCORE:
            print(safe_decode_string_from_bytes(plain_buf))
    print("--- CHALLENGE STATUS: COMPLETE ---")
