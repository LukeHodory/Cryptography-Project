
# !/usr/sbin/python3
from socket import *
import os
# import struct
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

# SERVER SIDE
# Secure Session Key Exchange Protocol #

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

    # Create hash digest
    myDigest = hashes.Hash(hashes.SHA256())
    myDigest.update(bytes(password, 'utf-8'))
    hashedPasswordAttempt = str(myDigest.finalize())

    # Read in hashed credentials from file
    with open('HashedCredentials.txt', 'r') as credentialsFile:
        credentials = credentialsFile.read().split('\n')

    # Put usernames and passwords into 2d array
    loginInfo = [['' for _ in range(2)] for _ in range(50)]
    for i in range(50):
        loginInfo[i][0] = credentials[i].split(' ', 1)[0]
        loginInfo[i][1] = credentials[i].split(' ', 1)[1]

    # Find index of username, if it exists
    goodUsername = False
    usernameIndex = 0
    for i in range(50):
        if username == loginInfo[i][0]:
            goodUsername = True
            break
        usernameIndex += 1

    # Check password associated with username
    goodPassword = False
    if goodUsername:
        goodPassword = (loginInfo[usernameIndex][1] == hashedPasswordAttempt)

    return goodUsername, goodPassword


def GenerateRSAPair():

    validLengths = 2048, 3072, 4096

    keyLength = int(input("Enter length of key (2048, 3072, or 4096): "))

    while keyLength not in validLengths:
        keyLength = int(input("Enter valid length of key: "))

    privateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=keyLength,)
    privatePem = privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())

    publicKey = privateKey.public_key()
    publicPem = publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    with (open('Private_Key' + str(keyLength) + '.pem', 'wb')
          as fw): fw.write(privatePem)
    with (open('Public_Key' + str(keyLength) + '.pem', 'wb')
          as fw): fw.write(publicPem)

    return keyLength


def RSAEncrypt(plainText, keyLength):

    with open('Public_Key' + str(keyLength) + '.pem', "rb") as key_file:
        publicKey = serialization.load_pem_public_key(key_file.read())

    ciphertext = publicKey.encrypt(plainText, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

    return ciphertext


def RSADecrypt(cipherText, keyLength):

    with open('Private_Key' + str(keyLength) + '.pem', "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None,)

    decryptedPlainText = private_key.decrypt(cipherText, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

    return decryptedPlainText


def main():
    replyMessage = 'login successful'
    badUsername = 'user name does not exist\n'
    badPassword = 'incorrect password\n'

    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.bind(('localhost', 8089))
    serverSocket.listen(1)
    print("The server is ready to receive requests")
    connectSocket, addr = serverSocket.accept()

    while 1:

        # Receive request from client
        encryptedRequest = connectSocket.recv(1024)
        request = decryptMessage(SECRET_KEY, encryptedRequest).decode("ascii")

        # Parse the request message to obtain username and password
        requestCommand = request.split('\t')[0]

        # Handling of login request information
        username = ''
        password = ''
        if requestCommand == "Disconnect": break
        if requestCommand == "Login":
            username = request.split('\t')[1]
            password = request.split('\t')[2]

        # Check the credential files to see whether the username
        #      exists and password is correct
        goodUsername, goodPassword = checkCreds(username, password)

        # Construct message with information about incorrect input
        if not goodPassword: replyMessage = badPassword
        if not goodUsername: replyMessage = badUsername

        # Construct the login response message and encrypt it before
        #   sending back to the client
        encryptedReply = encryptMessage(SECRET_KEY, replyMessage.encode())
        connectSocket.send(encryptedReply)
        if goodPassword: break

    connectSocket.close()


if __name__ == "__main__":
    main()
