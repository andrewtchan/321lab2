from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

def submit(user_string: str):
    sanitized_string = user_string.replace(";", "%3B").replace("=", "%3D")
    plaintext = "userid=456;userdata=" + sanitized_string + ";session-id=31337"
    print(plaintext)

def main():
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv

    submit(";admin=true")
    

if __name__ == "__main__":
    main()