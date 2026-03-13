# Sample Login Server
# Note: we are using the pyca/cryptography library as it can support
#   more complete crypto functions than Crypto dome (Crypto)

# !/usr/sbin/python3
from socket import *
import os
# import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

SECRET_KEY = b"0123456789abcdef" # 16 bytes = AES-128 (demo key)
BLOCK_SIZE_BITS = 128


def encryptMessage(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    padder = padding.PKCS7(BLOCK_SIZE_BITS).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv + ciphertext


def decryptMessage(key: bytes, data: bytes) -> bytes:
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(BLOCK_SIZE_BITS).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def main():

    ###################
    # Socket Creation #
    ###################

    # serverPort = 34567
    # create a welcome TCP socket
    serverSocket = socket(AF_INET, SOCK_STREAM)
    # serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # serverSocket.bind(("", serverPort))

    serverSocket.bind(('localhost', 8089))

    serverSocket.listen(1)
    print("The server is ready to receive requests")
    connectSocket, addr = serverSocket.accept()

    replyMessage = ''
    badUserName = 'user name does not exist\n'
    badPassword = 'incorrect password\n'
    successMessage = 'successful'

    ##########################
    # Server Protocol Design #
    ##########################
    while 1:
        encryptedRequest = connectSocket.recv(1024)
        # request = connectSocket.recv(1024).decode("ascii")
        # print('encrypted message: ', request)
        # print('encrypted message: ', encryptedRequest)

        request = decryptMessage(SECRET_KEY, encryptedRequest).decode("ascii")

        # Parse the request message to obtain username and password
        requestCommand = request.split('\t')[0]

        # Setting up for future request types
        # Line is also here to make PyCharm shut up about warnings
        if requestCommand == "Disconnect": break

        # Handling of login request
        userName = ''
        password = ''
        if requestCommand == "Login":
            userName = request.split('\t')[1]
            password = request.split('\t')[2]
            print("Username is: ", userName)
            print("Password is: ", password)

        # Read in credentials from file
        with open('credentials.txt', 'r') as credentialsFile:
            correctLogin = credentialsFile.read().split()

        # Check the credential files to see whether the username
        #   exists and passwords matches
        if (userName == correctLogin[0] and
            password == correctLogin[1]): replyMessage = successMessage

        # Send message with information about incorrect input
        if password != correctLogin[1]: replyMessage = badPassword
        if userName != correctLogin[0]: replyMessage = badUserName

        # Construct the login response message and encrypt it before
        #   sending back to the client
        encryptedReply = encryptMessage(SECRET_KEY, replyMessage.encode())
        connectSocket.send(encryptedReply)

    connectSocket.close()


if __name__ == "__main__":
    main()
