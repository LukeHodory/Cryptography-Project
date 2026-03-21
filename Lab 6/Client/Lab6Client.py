
# !/usr/bin/env python3
from socket import *
import os
# import struct
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa


"""Secure Session Key Exchange Protocol and Diagram"""
##############################################################################
#                                                                            #
#                     >>>---E(PUB-Se, [N1 || ID-A])--->>>                    #
#                     <<<---E(PUB-Cl, [N1 || N2])-----<<<                    #
#          +--------+                                    +--------+          #
#          | Client |                                    | Server |          #
#          +--------+                                    +--------+          #
#                     >>>---E(PUB-Se, N2)------------->>>                    #
#                     >>>---E(PUB-Se, E(PRI-Cl, Key))->>>                    #
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
#    (4c) ID will be username and password
# (5) Server creates Nonce 2
# (6) Server sends Nonce 1 and Nonce 2 as encrypted message
# (7) Client sends back Nonce 2 as encrypted message
# (8) Client encrypts session key using Client private key
# (9) Client sends encrypted session key encrypted with server public key

SESSION_KEY = os.urandom(16)
BLOCK_SIZE_BITS = 128
SuccessMessage = 'login successful'


def EncryptMessage(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    padder = padding.PKCS7(BLOCK_SIZE_BITS).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv + ciphertext


def DecryptMessage(key: bytes, data: bytes) -> bytes:
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(BLOCK_SIZE_BITS).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def Login():
    GenerateRSAPair()

    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect(('localhost', 8089))
    print('client connection successful\n')

    loginRequest = "KeyExchange" + "\t" + "" + "\t" + ""
    encryptedMsg = RSAEncrypt(loginRequest.encode())
    clientSocket.send(encryptedMsg)

    loginAttempts = 0
    while loginAttempts < 5:

        # TODO remove when manual input is needed
        loginRequest = "Login" + "\t" + "painters" + "\t" + "vp2aNk"

        # Encrypt and send message
        encryptedMsg = RSAEncrypt(loginRequest.encode())
        clientSocket.send(encryptedMsg)

        # Receive response from server
        serverResponse = clientSocket.recv(1024)
        decryptedServerResponse = RSADecrypt(serverResponse).decode("ascii")

        # Break loop if login success
        if decryptedServerResponse == SuccessMessage:
            print('login successful')
            break
        print(decryptedServerResponse)
        loginAttempts += 1

    # print out message too many logins without success
    if loginAttempts >= 5: print('too many login attempts')

    # Send disconnect signal
    loginRequest = "Disconnect" + "\t" + " " + "\t" + " "
    encryptedMsg = EncryptMessage(SESSION_KEY, loginRequest.encode())
    clientSocket.send(encryptedMsg)
    clientSocket.close()


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

    with open('../Server/Server_Public_Key.pem', "rb") as key_file:
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
    return str(-1)


def KeyExchange():
    GenerateRSAPair()

    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect(('localhost', 8089))
    print('client connection successful\n')

    nonce1 = CreateNonce()

    loginRequest = "KeyExchange" + "\t" + nonce1 + "\t" + "luke"
    encryptedMsg = RSAEncrypt(loginRequest.encode())
    clientSocket.send(encryptedMsg)

    encryptedMsg = EncryptMessage(SESSION_KEY, loginRequest.encode())
    clientSocket.send(encryptedMsg)

    clientSocket.close()


if __name__ == "__main__":
    GenerateRSAPair()
