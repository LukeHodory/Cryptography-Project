
# !/usr/bin/env python3
from socket import *
import os
import bcrypt
# import struct
# from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa


"""Secure Session Key Exchange Protocol and Diagram"""
##############################################################################
#                                                                            #
#                  >>-----E(PUB-Se, [N1 || ID-A])------->>                   #
#                  <<-----E(PUB-Cl, [N1 || N2])---------<<                   #
#          +--------+                                    +--------+          #
#          | Client |                                    | Server |          #
#          +--------+                                    +--------+          #
#                  >>-----E(PUB-Se, N2)------------------>>                  #
#                  >>-----E(PUB-Se, Key))------>>                  #
#                  >>-----E(PUB-Se, E(Key, Password-A))-->>                  #
#                                                                            #
##############################################################################

# (1) Public/Private key creation on both sides
#    (1a) Method: GenerateKey()
# (2) Both client and server send out public keys
# (3) Creation of Nonce 1 on client side
#    (3a) Method: CreateNonce()
#    (3b) For now, nonce will just be -1 on client side
#    (3c) -2 on server side
#    (3d) Will create proper nonce later
# (4) Client sends Nonce 1 and identifier as encrypted message
#    (4a) Method: RSAEncrypt()
#    (4b) Method: RSADecrypt()
#    (4c) ID will be username
# (5) Server creates Nonce 2
# (6) Server sends Nonce 1 and Nonce 2 as encrypted message
# (7) Client sends back Nonce 2 as encrypted message
# (8) Client encrypts session key using Client private key
# (9) Client sends encrypted session key encrypted with server public key
# (10) Client sends password encrypted with session key
# (11) Server decrypts key and responds with encrypted message about login
#    success
# (12) Repeat (10) and (11) until username is found in list of server
#    credentials and the corresponding password matches,
#    or until 5 failed login attempts

SESSION_KEY = os.urandom(128)
SECRET_KEY = '0123456789abcdef'
BLOCK_SIZE_BITS = 256
SuccessMessage = 'login successful'


def GenerateRSAPair():

    keyLength = 3072

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

    with (open('Client_Private_Key.pem', 'wb')
          as fw): fw.write(privatePem)
    with (open('Client_Public_Key.pem', 'wb')
          as fw): fw.write(publicPem)

    return keyLength


def RSAEncrypt(plainText):

    with open('Server_Public_Key.pem', "rb") as key_file:
        publicKey = serialization.load_pem_public_key(key_file.read())

    ciphertext = publicKey.encrypt(plainText, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

    return ciphertext


def RSADecrypt(cipherText):

    with open('Client_Private_Key.pem', "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None,)

    decryptedPlainText = private_key.decrypt(cipherText, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

    return decryptedPlainText


def CreateNonce():
    return 'Client Nonce'


def KeyExchange(clientSocket, username):
    myNonce = CreateNonce()
    nonceMessage = username + "\t" + myNonce

    # Step 1, send first nonce
    encryptedNonce = RSAEncrypt(nonceMessage.encode())
    clientSocket.send(encryptedNonce)

    # Step 2, receive first and second nonce
    nonceResponse = clientSocket.recv(1024)
    decryptedNonceResponse = RSADecrypt(nonceResponse).decode("ascii")

    firstNonce = decryptedNonceResponse.split('\t')[0]
    newNonce = decryptedNonceResponse.split('\t')[1]

    if firstNonce != myNonce:
        print('Reply nonce does not match what was sent')
        clientSocket.close()
        exit()

    # Step 3, send back second nonce
    encryptedReplyNonce = RSAEncrypt(newNonce.encode())
    clientSocket.send(encryptedReplyNonce)

    clientSocket.recv(1024)

    # Step 4, send session key
    keyShare = RSAEncrypt(SESSION_KEY)
    clientSocket.send(keyShare)

    return True


def Login(clientSocket, password, username):

    # TODO use session key to encrypt loginInfo before RSA encrypt

    successMessage = 'Login Successful\n'
    loginSuccess = False

    loginInfo = password + "\t" + username

    encryptedPassword = RSAEncrypt(loginInfo.encode())
    clientSocket.send(encryptedPassword)

    loginResponse = clientSocket.recv(1024)
    decryptedLoginResponse = RSADecrypt(loginResponse).decode("ascii")

    if decryptedLoginResponse == successMessage: loginSuccess = True

    return loginSuccess, decryptedLoginResponse


def ConnectToServer():

    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect(('localhost', 8089))
    print('server connection successful\n')

    username = 'painters'
    password = 'vp2aNk'

    if not KeyExchange(clientSocket, username):
        clientSocket.close()
        exit()

    loginAttempts = 0
    while loginAttempts < 5:
        loginSuccess, loginMessage = Login(clientSocket, password, username)

        if loginSuccess:
            print('Login Successful!')
            break
        loginAttempts += 1

        print(loginMessage)

        username = input('username: ')
        password = input('password: ')

    # print out message too many logins without success
    if loginAttempts >= 5: print('too many login attempts')

    clientSocket.close()


if __name__ == "__main__":
    ConnectToServer()
