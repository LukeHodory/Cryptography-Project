
# !/usr/sbin/python3
from socket import *
import os
# import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

SECRET_KEY = b"0123456789abcdef"  # 16 bytes = AES-128 (demo key)
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


def checkCreds(username, password):
    
    ## Read in hashed credentials from file
    with open('hashedCredentials.txt', 'r') as credentialsFile:
        credentials = credentialsFile.read().split()

    loginInfo = [['' for _ in range(2)] for _ in range(50)]
    for i in range(100): loginInfo[int(i / 2)][i % 2] = credentials[i]

    myDigest = hashes.Hash(hashes.SHA256())
    myDigest.update(bytes(password, 'utf-8'))
    hashedPasswordAttempt = str(myDigest.finalize())

    ## Read in hashed credentials from file
    with open('hashedCredentials.txt', 'r') as credentialsFile:
        credentials = credentialsFile.read().split('\n')

    ## convert stored credentials into 2D array
    loginInfo = [['' for _ in range(2)] for _ in range(50)]
    for i in range(50):
        loginInfo[i][0] = credentials[i].split(' ', 1)[0]
        loginInfo[i][1] = credentials[i].split(' ', 1)[1]

    ## Check the credential files to see whether the username
    ##      exists and password is correct
    goodUsername = False
    usernameIndex = 0
    for i in range(50):
        if username == loginInfo[i][0]:
            goodUsername = True
            break
        usernameIndex += 1

    goodPassword = False
    if goodUsername:
        print('username found')
        print(loginInfo[usernameIndex][1])
        print(hashedPasswordAttempt + '\n')
        goodPassword = (loginInfo[usernameIndex][1] == hashedPasswordAttempt)

    return goodUsername, goodPassword


def main():
    replyMessage = 'login successful'
    badUsername = 'user name does not exist\n'
    badPassword = 'incorrect password\n'

    ###################
    # Socket Creation #
    ###################

    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.bind(('localhost', 8089))
    serverSocket.listen(1)
    print("The server is ready to receive requests")
    connectSocket, addr = serverSocket.accept()

    ##########################
    # Server Protocol Design #
    ##########################

    while 1:

        encryptedRequest = connectSocket.recv(1024)

        request = decryptMessage(SECRET_KEY, encryptedRequest).decode("ascii")

        ## Parse the request message to obtain username and password
        requestCommand = request.split('\t')[0]

        ## Setting up for future request types
        if requestCommand == "Disconnect": break

        ## Handling of login request information
        username = ''
        password = ''
        if requestCommand == "Login":
            username = request.split('\t')[1]
            password = request.split('\t')[2]

        ## Check the credential files to see whether the username
        ##      exists and password is correct
        goodUsername, goodPassword = checkCreds(username, password)

        ## construct message with information about incorrect input
        if not goodPassword: replyMessage = badPassword
        if not goodUsername: replyMessage = badUsername

        ## Construct the login response message and encrypt it before
        ##   sending back to the client
        encryptedReply = encryptMessage(SECRET_KEY, replyMessage.encode())
        connectSocket.send(encryptedReply)
        if goodPassword: break

    connectSocket.close()


if __name__ == "__main__":
    main()
