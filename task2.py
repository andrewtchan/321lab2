from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

def submit(key: bytes, iv: bytes, user_string: str):
    # URL encode ; and = characters
    sanitized_string = user_string.replace(";", "%3B").replace("=", "%3D")
    plaintext = ("userid=456;userdata=" + sanitized_string + ";session-id=31337").encode()

    # pad content using PKCS#7
    padded_content = plaintext + (chr(16 - len(plaintext) % 16) * (16 - len(plaintext) % 16)).encode()

    # encrypt padded_content with CBC
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(padded_content)

def verify(key: bytes, iv: bytes, ciphertext: bytes):
    # decrypt ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = cipher.decrypt(ciphertext) # no .decode() here because scrambled first block may have non-ascii characters
    print(plaintext)
    if plaintext.find(b';admin=true;') > 0:
        return True
    else:
        return False

def main():
    key = get_random_bytes(16)
    iv = get_random_bytes(16)

    ciphertext = submit(key, iv, "aaaaaaaaaaaa")

    # block 1: userid=456;userd
    # block 2: ata=aaaaaaaaaaaa
    # change c1 of ciphertext to c1 xor p2 xor <payload>, then call verify
    c1_xor_p2 = bytes(a ^ b for a, b in zip(ciphertext[0:16], ("ata=aaaaaaaaaaaa").encode()))
    then_xor_payload = bytes(a ^ b for a, b in zip(c1_xor_p2, ("ata=;admin=true;").encode()))
    new_ciphertext = then_xor_payload + ciphertext[16:]

    print(verify(key, iv, new_ciphertext))

    
    

if __name__ == "__main__":
    main()