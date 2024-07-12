# Text-encryption-file
from cryptography.fernet import Fernet
import argparse
import os

# Function to generate a key and save it into a file
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    print("Key generated and saved to secret.key")

# Function to load the key from the current directory named `secret.key`
def load_key():
    return open("secret.key", "rb").read()

# Function to encrypt a message
def encrypt_message(message):
    key = load_key()
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

# Function to decrypt an encrypted message
def decrypt_message(encrypted_message):
    key = load_key()
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)
    return decrypted_message.decode()

# Command-line interface
def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt a message.")
    parser.add_argument("action", choices=["encrypt", "decrypt", "generate-key"], help="Action to perform")
    parser.add_argument("message", nargs='?', help="The message to encrypt or decrypt")

    args = parser.parse_args()

    if args.action == "generate-key":
        generate_key()
    elif args.action == "encrypt":
        if not os.path.exists("secret.key"):
            print("Key not found. Generate a key first using 'generate-key' action.")
            return
        encrypted = encrypt_message(args.message)
        print(f"Encrypted message: {encrypted.decode()}")
    elif args.action == "decrypt":
        if not os.path.exists("secret.key"):
            print("Key not found. Generate a key first using 'generate-key' action.")
            return
        try:
            decrypted = decrypt_message(args.message.encode())
            print(f"Decrypted message: {decrypted}")
        except Exception as e:
            print("Failed to decrypt message. Ensure the message is correctly encrypted and the key is correct.")

if __name__ == "__main__":
    main()
