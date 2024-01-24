from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

def ecb_encrypt(key, raw_data):
    # convert raw data (string) to byte string, pad with bytes
    padded_data = pad(raw_data.encode(), AES.block_size)

    # create an AES-128 cipher with the given key
    cipher = AES.new(key, AES.MODE_ECB)

    # encrypt padded data with cipher
    encrypted_data = cipher.encrypt(padded_data)

    # encode ciphertext to printable ascii
    return b64encode(encrypted_data)

def ecb_decrypt(key, enc_ct):
    # decode ascii to ciphertext bytes
    ciphertext = b64decode(enc_ct)

    # recreate cipher
    cipher = AES.new(key, AES.MODE_ECB)

    # decrypt ciphertext bytes with cipher, remove padding
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

def cbc_encrypt(key, raw_data):
    # creates cipher
    cipher = AES.new(key, AES.MODE_CBC)

    # Encrypts data and returns cipher text
    return b64encode(cipher.encrypt(pad(raw_data.encode(), AES.block_size))), cipher.iv

def cbc_decrypt(key, enc_ct, IV):
    # re-creates cipher
    cipher = AES.new(key, AES.MODE_CBC, IV)

    # decrypts data and returns it
    return unpad(cipher.decrypt(b64decode(enc_ct)), AES.block_size)

def main():
    # library test
    data = "secret message"
    aes_key = get_random_bytes(16)

    encrypted = ecb_encrypt(aes_key, data)
    decrypted = ecb_decrypt(aes_key, encrypted)

    # CBC encryption-decryption
    encrypted_cbc, IV = cbc_encrypt(aes_key, data)
    decrypted_cbc = cbc_decrypt(aes_key, encrypted_cbc, IV)

    print(encrypted.decode())
    print(decrypted.decode())
    print(encrypted_cbc.decode())
    print(decrypted_cbc.decode())

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

    # CBC - encrypting the image
    logo = open("cp-logo.bmp", "rb")
    data_cbc = logo.read()
    logo.close()
    header_cbc = data_cbc[:54]
    content_cbc = data_cbc[54:]
    key_cbc = get_random_bytes(16)
    cipher_cbc = AES.new(key_cbc, AES.MODE_CBC)
    padded_content_cbc = content_cbc + (chr(16 - len(content_cbc) % 16) * (16 - len(content_cbc) % 16)).encode()
    out_cbc = open("cbc-logo.bmp", "wb")
    cipher_text_cbc = header_cbc
    for i in range(len(padded_content_cbc) // 16):
        plaintext_cbc = padded_content_cbc[i*16:(i*16)+16]
        cipher_text_cbc += cipher_cbc.encrypt(plaintext_cbc)
    out_cbc.write(cipher_text_cbc)
    out_cbc.close()

    out.write(cipher_text)
    out.close()
    

if __name__ == "__main__":
    main()