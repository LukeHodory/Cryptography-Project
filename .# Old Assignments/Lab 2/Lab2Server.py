# Sample Login Server
# Note: we are using the pyca/cryptography library as it can support
#   more complete crypto functions than Crypto dome (Crypto)

# !/usr/sbin/python3
from socket import *
import os
import struct
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


def main():
    serverPort = 34567

    # create a welcome TCP socket
    serverSocket = socket(AF_INET, SOCK_STREAM)

    # serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverSocket.bind(("", serverPort))
    serverSocket.listen(1)
    print("The server is ready to receive requests")

    while 1:
        # Create connection socket when sensing new connection request
        connectSocket, addr = serverSocket.accept()

        # request=connectSocket.recv(1024).decode("ascii")
        encryptedRequest = connectSocket.recv(1024)
        request = decrypt_message(SECRET_KEY,
                                  encryptedRequest).decode("ascii")
        print(request)

        # Parse the request message to obtain username and password
        requestCommand = request.split('\t')[0]

        # Handling of login request
        if requestCommand == "Login":
            userName = request.split('\t')[1]
            password = request.split('\t')[2]
            print("Username is: ", userName)
            print("Password is: ", password)

        # Check the credential files to see whether the username
        #   exists and passwords matches
        # Construct the login response message and encrypt it before
        #   sending back to the client

        connectSocket.close()


if __name__ == "__main__":
    main()
