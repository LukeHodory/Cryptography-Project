from socket import *
import os
import bcrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

BLOCK_SIZE_BITS = 256
myLocation = 'Server'
thatLocation = 'Client'


def CreateBcryptHashFile() -> None:
    with open('Credentials.txt', 'r') as credentialsFile:
        loginFile = credentialsFile.read().split()

    loginInfo = [['' for _ in range(2)] for _ in range(50)]
    for i in range(100):
        loginInfo[int(i / 2)][i % 2] = loginFile[i]

    with open('BcryptCreds.txt', 'w') as hashedFile:
        for myInfo in loginInfo:
            myPassword = myInfo[1]
            myPasswordHashed = bcrypt.hashpw(bytes(myPassword, 'utf-8'),
                                             bcrypt.gensalt())
            hashedFile.write(myInfo[0] + ' ')
            hashedFile.write(str(myPasswordHashed) + '\n')


def GenerateRSAPair(thisLocation: str) -> None:
    # thisLocation = machine this private key is for
    # "Server" in this case

    keyLength = 3072
    privateFile = thisLocation + '_Private_Key.pem'
    publicFile = thisLocation + '_Public_Key.pem'

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

    with (open(privateFile, 'wb')
          as fw): fw.write(privatePem)
    with (open(publicFile, 'wb')
          as fw): fw.write(publicPem)


def SymEncrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    padder = padding.PKCS7(BLOCK_SIZE_BITS).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv + ciphertext


def SymDecrypt(key: bytes, cipherText: bytes) -> bytes:
    iv = cipherText[:16]
    ciphertext = cipherText[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(BLOCK_SIZE_BITS).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def RSAEncrypt(plainText: bytes) -> bytes:
    with open('../Client/Client_Public_Key.pem', "rb") as key_file:
        publicKey = serialization.load_pem_public_key(key_file.read())

    ciphertext = publicKey.encrypt(plainText, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

    return ciphertext


def RSADecrypt(cipherText: bytes) -> bytes:

    with open('Server_Private_Key.pem', "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None,)

    decryptedPlainText = private_key.decrypt(cipherText, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

    return decryptedPlainText


def GenerateNonce() -> str:
    return 'Server Nonce'


def ServerSideKeyExchange(serverSocket, firstNonce: str) -> bytes:
    newNonce = GenerateNonce()
    nonceReply = firstNonce + "\t" + GenerateNonce()

    # Step 2, send first and second nonce
    encryptedReply = RSAEncrypt(nonceReply.encode())
    serverSocket.send(encryptedReply)

    # Step 3, receive back second nonce
    nonceResponse = serverSocket.recv(1024)

    decryptedNonceResponse = RSADecrypt(nonceResponse).decode("ascii")
    if decryptedNonceResponse != newNonce:
        message = 'Reply nonce does not match what was sent'
        print(message)
        serverSocket.send(message)
        serverSocket.close()
        exit()

    wait = 'wait'
    serverSocket.send(wait.encode())

    # Step 4, receive session key
    encryptedKey = serverSocket.recv(1024)
    # sessionKey = RSADecrypt(encryptedKey).decode("ascii")
    sessionKey = RSADecrypt(encryptedKey)

    return sessionKey


def ServerSideLogin(sessionKey: bytes, username: str, password: str) -> str:

    badUsername = 'User name does not exist\n'
    badPassword = 'Incorrect password\n'
    replyMessage = 'Login Successful\n'

    # Read in creds from file into array
    with open('BcryptCreds.txt', 'r') as credentialsFile:
        credentials = credentialsFile.read().split('\n')
    creds = [['' for _ in range(2)] for _ in range(50)]
    for i in range(50):
        creds[i][0] = credentials[i].split(' ', 1)[0]
        creds[i][1] = credentials[i].split(' ', 1)[1]

    # Find index of username, if it exists
    usernameIndex = 0
    for i in range(50):
        if username == creds[i][0]: break
        usernameIndex += 1

    print('server version: ', creds[usernameIndex][1])
    print('sent version: ', password)

    # If index is greater that amount of usernames
    #    username was not found
    goodUsername = (usernameIndex <= len(creds))
    print('username: ', username)
    print('username status: ', goodUsername)

    # Check password associated with username
    goodPassword = False
    if goodUsername:
        goodPassword = (bcrypt.checkpw(password))
    print('password status: ', goodPassword)

    if not goodPassword: replyMessage = badPassword
    if not goodUsername: replyMessage = badUsername

    return replyMessage


def ConnectToClient():

    # Create Socket
    newSocket = socket(AF_INET, SOCK_STREAM)
    newSocket.bind(('localhost', 8089))
    newSocket.listen(1)
    print("The server is ready to receive requests")
    serverSocket, addr = newSocket.accept()

    # Step 1, receive first nonce
    encryptedRequest = serverSocket.recv(1024)
    keyExchangeInfo = RSADecrypt(encryptedRequest).decode("ascii")
    clientNonce = keyExchangeInfo.split('\t')[1]

    sessionKey = ServerSideKeyExchange(serverSocket, clientNonce)

    loginInfo = serverSocket.recv(1024)
    decryptedLoginInfo = RSADecrypt(loginInfo).decode("ascii")
    password = decryptedLoginInfo.split('\t')[0]
    username = decryptedLoginInfo.split('\t')[1]

    loginStatus = ServerSideLogin(sessionKey, username, password)

    encryptedLoginStatus = RSAEncrypt(loginStatus.encode())
    serverSocket.send(encryptedLoginStatus)


if __name__ == "__main__":
    ConnectToClient()
