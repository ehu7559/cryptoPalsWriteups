#Challenge 1: Convert hex to base64
from base64 import b64encode

#Hexadecimal --> Base64 function
def hex_to_base64(hex_string: str) -> bytes:
    '''str -> str\nConverts a hex string to base64 string.'''
    return b64encode(bytes.fromhex(hex_string))

#Challenge Code
if __name__ == "__main__":
    print(str(hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")))
    print("--- CHALLENGE STATUS: COMPLETE ---")