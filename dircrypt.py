# this app is a simple console app to encrypt and decrypt files contents of a given directory
# it would take 3 arguments from the user
# 1. the path to the directory
# 2. the operation to perform (encrypt or decrypt)
# 3. the key to use for the operation
# the app would then perform the operation on all the files in the directory and its subdirectories
# the app would also detect if the file is already encrypted or decrypted and would skip it

import base64
import hashlib
import os
import sys
import argparse
from getpass import getpass 
from cryptography.fernet import Fernet

def encrypt_file(file_path, key):
    # read the file contents
    with open(file_path, 'rb') as file:
        data = file.read()

    # check if the file is already encrypted
    if data.startswith(b'gAAAAA'):
        print(f'Skipped: {file_path} (already encrypted)')
        return

    # encrypt the file contents
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)

    # write the encrypted data back to the file
    with open(file_path, 'wb') as file:
        file.write(encrypted_data)

    print(f'Encrypted: {file_path}')
    

def decrypt_file(file_path, key):
    # read the file contents
    with open(file_path, 'rb') as file:
        data = file.read()

    # check if the file is already decrypted
    if not data.startswith(b'gAAAAA'):
        print(f'Skipped: {file_path} (already decrypted)')
        return

    # decrypt the file contents
    fernet = Fernet(key)
    try:
        decrypted_data = fernet.decrypt(data)
    except Exception:
        print(f'Skipped: {file_path} (invalid key or not an encrypted file)')
        return

    # write the decrypted data back to the file
    with open(file_path, 'wb') as file:
        file.write(decrypted_data)

    print(f'Decrypted: {file_path}')

def process_directory(directory, operation, key):
    # walk through the directory and its subdirectories
    for root, dirs, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)

            # perform the operation on the file
            if operation == 'encrypt':
                encrypt_file(file_path, key)
            elif operation == 'decrypt':
                decrypt_file(file_path, key)

def main():
    # parse the command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', help='The path to the directory')
    parser.add_argument('operation', help='The operation to perform (encrypt or decrypt)', choices=['encrypt', 'decrypt'])
    args = parser.parse_args()

    # check if the directory exists
    if not os.path.exists(args.directory):
        print('The directory does not exist')
        sys.exit(1)

    

    # get the key from the user as password and convert the key to a 32-byte key
    key = getpass('Enter the encryption key: ')
    key = base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest())

    # perform the operation on the directory
    process_directory(args.directory, args.operation, key)

if __name__ == '__main__':
    main()

# to run the app in the terminal
# run the following command in the terminal
# python dircrypt.py <directory> <operation>
# i.e.: python dircrypt.py /path/to/directory encrypt
    
# to compile the app to a standalone executable
# run the following command in the terminal
# pyinstaller dircrypt.py --onefile
