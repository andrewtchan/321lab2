from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

def ecb_encrypt(key, raw_data):
    # convert raw data to byte string, pad with bytes
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

def main():
    data = "secret message"
    aes_key = get_random_bytes(16)

    encrypted = ecb_encrypt(aes_key, data)
    decrypted = ecb_decrypt(aes_key, encrypted)

    print(encrypted.decode())
    print(decrypted.decode())

    

if __name__ == "__main__":
    main()