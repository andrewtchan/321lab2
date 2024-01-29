from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

def main():
    # ECB
    f = open("cp-logo.bmp", "rb")
    data = f.read()
    f.close()
    header = data[:54]
    content = data[54:]
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)

    # pad content using PKCS#7
    padded_content = content + (chr(16 - len(content) % 16) * (16 - len(content) % 16)).encode()

    # prepend header & write to output file
    out = open("ecb-logo.bmp", "wb")
    cipher_text = header

    # divide content into 16 byte chunks, encrypt using library AES cipher
    for i in range(len(padded_content) // 16):
        plaintext = padded_content[i*16:(i*16)+16]
        cipher_text += cipher.encrypt(plaintext)
    
    out.write(cipher_text)
    out.close()

    # CBC
    logo = open("cp-logo.bmp", "rb")
    data_cbc = logo.read()
    logo.close()

    # split bmp into header and content
    header_cbc = data_cbc[:54]
    content_cbc = data_cbc[54:]

    # generate key and iv, AES primitive
    key_cbc = get_random_bytes(16)
    iv = get_random_bytes(16)
    cipher_cbc = AES.new(key_cbc, AES.MODE_ECB)

    #pad with PKCS#7
    padded_content_cbc = content_cbc + (chr(16 - len(content_cbc) % 16) * (16 - len(content_cbc) % 16)).encode()
    
    # encrypt and write to out
    out_cbc = open("cbc-logo.bmp", "wb")
    cipher_text_cbc = header_cbc

    prev = iv
    for i in range(len(padded_content_cbc) // 16):
        plaintext_cbc = padded_content_cbc[i*16:(i*16)+16]
        xored = bytes(a ^ b for a, b in zip(plaintext_cbc[0:16], prev))
        encrypted_cbc = cipher_cbc.encrypt(xored)
        cipher_text_cbc += encrypted_cbc
        prev = encrypted_cbc

    out_cbc.write(cipher_text_cbc)
    out_cbc.close()
    

if __name__ == "__main__":
    main()