# Sample program for login client

# !/usr/bin/env python3
from socket import *
import os
# import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

SECRET_KEY = b"0123456789abcdef" # 16 bytes = AES-128 (demo key)

BLOCK_SIZE_BITS = 128


def encrypt_message(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    padder = padding.PKCS7(BLOCK_SIZE_BITS).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv + ciphertext


def decrypt_message(key: bytes, data: bytes) -> bytes:
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(BLOCK_SIZE_BITS).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# Start of the client main program
def main():
    # Create socket to connect with the server side
    server = "10.0.2.4"
    serverPort = 34567
    clientSocket = socket(AF_INET, SOCK_STREAM)
    # clientSocket.connect((server, serverPort))
    clientSocket.connect(('localhost', 8089))
    print('client connection successful')

    # Prepare a login message
    userName = input("Input the user name:")
    password = input("Input the password:")
    loginRequest = "Login"+"\t"+userName+"\t"+password

    # Encrypt the message
    encryptedMsg = encrypt_message(SECRET_KEY, loginRequest.encode())

    # Send the encrypted message to the server
    clientSocket.send(encryptedMsg)

    # Receive the response from the server
    serverResponse = clientSocket.recv(1024)

    # Decrypt the received response Message
    # Decode the message to string (using decode("ascii") )
    # Parse the response message
    # If it is response to the login request, and it indicates success,
    #   print the message that login succeeded
    # else, print that the login attempt failed.
    # Close the connection socket when the session is done
    clientSocket.close()


if __name__ == "__main__":
    main()
