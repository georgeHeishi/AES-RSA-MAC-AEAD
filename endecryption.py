import sys
import json
import os
import time
from base64 import b64encode
from base64 import b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

BUFFER_SIZE = 65536


def encrypt(read_data_location):
    filename, file_extension = os.path.splitext(read_data_location)

    write_data_location = filename + "_encrypted" + file_extension

    # Generate key
    key = get_random_bytes(16)

    # Generating private key (RsaKey !object! 1024 bits) and public key
    private_key = RSA.generate(1024)
    public_key = private_key.publickey()

    # https://stackoverflow.com/questions/64951915/encrypt-a-big-file-that-does-not-fit-in-ram-with-aes-gcm
    # Instantiating PKCS1_OAEP object with the public key for encryption
    # Encrypted key is 128 bytes long
    key_cipher = PKCS1_OAEP.new(key=public_key)
    key_encrypted = key_cipher.encrypt(key)

    # Create cipher for encrypting (nonce is default 16 bytes long)
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce

    # Open files for reading and writing
    read_data_file = open(read_data_location, "rb")
    write_data_file = open(write_data_location, "wb")

    # Write header
    write_data_file.write(key_encrypted)
    write_data_file.write(nonce)
    write_data_file.write(get_random_bytes(16))
    print("ENCRYPTION IS STARTING NOW!")

    # Read, encrypt write data
    start_time = time.time()

    while data := read_data_file.read(BUFFER_SIZE):
        encrypted_data = cipher.encrypt(data)
        write_data_file.write(encrypted_data)

    print("Encryption is done and took: %s seconds" % (time.time() - start_time))

    # Create MAC tag at write it at the beginning of encrypted file (tag 16 bytes)
    tag = cipher.digest()
    write_data_file.seek(16 + 128)
    write_data_file.write(tag)

    print("KEY: ", key)
    print("TAG: ", tag)
    print("NONCE: ", nonce)

    # Close read and written data files
    read_data_file.close()
    write_data_file.close()

    with open('private.bin', 'wb') as pr:
        pr.write(private_key.export_key())
    with open('public.bin', 'wb') as pu:
        pu.write(public_key.export_key())


def decrypt(read_data_location):
    with open('private.bin', 'rb') as pr:
        private_key = RSA.import_key(pr.read())

    key_cipher = PKCS1_OAEP.new(key=private_key)

    filename, file_extension = os.path.splitext(read_data_location)

    write_data_location = filename + "_decrypted" + file_extension

    # Open encrypted file
    encrypted_data_file = open(read_data_location, "rb")
    decrypted_data_file = open(write_data_location, "wb")

    # Read encrypted key (first 128 bytes), nonce (next 16 bytes) and tag (last 16 bytes)
    key = key_cipher.decrypt(encrypted_data_file.read(128))
    nonce = encrypted_data_file.read(16)
    tag = encrypted_data_file.read(16)

    print("KEY: ", key)
    print("TAG: ", tag)
    print("NONCE: ", nonce)

    # Create cipher
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        print("DECRYPTION IS STARTING NOW!")

        # Read, decrypt, write data
        while encrypted_data := encrypted_data_file.read(BUFFER_SIZE):
            decrypted_data = cipher.decrypt(encrypted_data)
            decrypted_data_file.write(decrypted_data)

        cipher.verify(tag)
        print("Decrypted file: " + write_data_location)
    except:
        print("File corrupted!")
    finally:
        encrypted_data_file.close()
        decrypted_data_file.close()


def validate_path(path, func):
    if not os.path.isfile(path):
        print("Destination is not a file!")
        return func()
    elif path == "q" or path == "Q" or path == ":q":
        exit()
    else:
        return path


def encryption_input():
    path = input("Enter path of file to ENCRYPT: ")
    return validate_path(path, encryption_input)


def decryption_input():
    path = input("Enter path of file to DECRYPT: ")
    return validate_path(path, decryption_input)


def choose_mode():
    print("-" * 40 + "\n")
    print("To ENCRYPT enter E")
    print("To DECRYPT enter D")
    mode_input = input("Enter mode: ")

    if mode_input == "E" or mode_input == "e":
        encrypt_path = encryption_input()

        encrypt(encrypt_path)
    elif mode_input == "D" or mode_input == "d":
        print("")
        decrypt_path = decryption_input()

        start_time = time.time()
        decrypt(decrypt_path)
        print("Decryption is done and took: %s seconds" % (time.time() - start_time))
    elif mode_input == "q" or mode_input == "Q" or mode_input == "q":
        exit()
    else:
        print("Wrong input! To exit application enter q\n")
        return choose_mode()

    return mode_input


# Start application
print("Encrypt/Decrypt console app")
mode = choose_mode()
