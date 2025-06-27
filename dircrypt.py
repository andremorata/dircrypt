# This console application encrypts and decrypts the contents of files within a specified directory and its subdirectories.
# It takes two arguments from the user:
# 1. The path to the directory.
# 2. The operation to perform (encrypt or decrypt).
# The application will prompt for a password, which is used to derive an encryption key with a unique salt embedded in each file.
# It detects if a file is already encrypted/decrypted by this tool and skips it accordingly.

import base64
import hashlib
import os
import sys
import argparse
from getpass import getpass 
from cryptography.fernet import Fernet, InvalidToken

HEADER = b'DIRCRYPT_V1'
SALT_LENGTH = 16

def encrypt_file(file_path, password):
    try:
        # read the file contents
        with open(file_path, 'rb') as file:
            data = file.read()
    except IOError:
        print(f'Error: Could not read file {file_path}')
        return

    # check if the file is already encrypted
    if data.startswith(HEADER):
        print(f'Skipped: {file_path} (already encrypted)')
        return

    # Generate a new salt for each file
    salt = os.urandom(SALT_LENGTH)
    key = base64.urlsafe_b64encode(hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32))

    # encrypt the file contents
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)

    # Prepend header and salt to the encrypted data
    final_data = HEADER + salt + encrypted_data

    try:
        # write the encrypted data back to the file
        with open(file_path, 'wb') as file:
            file.write(final_data)
    except IOError:
        print(f'Error: Could not write to file {file_path}')
        return

    print(f'Encrypted: {file_path}')
    

def decrypt_file(file_path, password):
    try:
        # read the file contents
        with open(file_path, 'rb') as file:
            data = file.read()
    except IOError:
        print(f'Error: Could not read file {file_path}')
        return

    # check if the file is encrypted by this tool
    if not data.startswith(HEADER):
        print(f'Skipped: {file_path} (not an encrypted file or encrypted with a different tool)')
        return

    # Extract salt and encrypted data
    salt = data[len(HEADER):len(HEADER) + SALT_LENGTH]
    encrypted_data = data[len(HEADER) + SALT_LENGTH:]

    # Derive key using the extracted salt and user's password
    key = base64.urlsafe_b64encode(hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32))

    # decrypt the file contents
    fernet = Fernet(key)
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except InvalidToken:
        print(f'Skipped: {file_path} (invalid key or corrupted data)')
        return

    try:
        # write the decrypted data back to the file
        with open(file_path, 'wb') as file:
            file.write(decrypted_data)
    except IOError:
        print(f'Error: Could not write to file {file_path}')
        return

    print(f'Decrypted: {file_path}')

def process_directory(directory, operation, password):
    script_path = os.path.abspath(__file__)
    # walk through the directory and its subdirectories
    for root, dirs, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)

            # Skip the script itself
            if os.path.abspath(file_path) == script_path:
                print(f'Skipped: {file_path} (dircrypt.py script itself)')
                continue

            # perform the operation on the file
            if operation == 'encrypt':
                encrypt_file(file_path, password)
            elif operation == 'decrypt':
                decrypt_file(file_path, password)

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

    

    password = getpass('Enter the encryption key: ')

    # perform the operation on the directory
    process_directory(args.directory, args.operation, password)

if __name__ == '__main__':
    main()

# to run the app in the terminal
# run the following command in the terminal
# python dircrypt.py <directory> <operation>
# i.e.: python dircrypt.py /path/to/directory encrypt
    
# to compile the app to a standalone executable
# run the following command in the terminal
# pyinstaller dircrypt.py --onefile
