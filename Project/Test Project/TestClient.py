from socket import *
from Project import ExtraCode
import os
import bcrypt


"""Secure Session Key Exchange Protocol and Diagram"""
##############################################################################
#                                                                            #
#                  >>-----E(PUB-Se, [N1 || ID-A])------->>                   #
#                  <<-----E(PUB-Cl, [N1 || N2])---------<<                   #
#          +--------+                                    +--------+          #
#          | Client |                                    | Server |          #
#          +--------+                                    +--------+          #
#                  >>-----E(PUB-Se, N2)------------------>>                  #
#                  >>-----E(PUB-Se, Key))---------------->>                  #
#                  >>-----E(PUB-Se, E(Key, Password-A))-->>                  #
#                                                                            #
##############################################################################

# (1) Public/Private key creation on both sides
#    (1a) Method: GenerateKey()
# (2) Both client and server send out public keys
# (3) Creation of Nonce 1 on client side
#    (3a) Method: CreateNonce()
#    (3b) For now, nonce will just be 'client nonce' on client side
#    (3c) 'server nonce' on server side
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

myLocation = 'Test_Client'
thatLocation = 'Test_Server'

successMessage = 'Login Successful\n'
disconnectMessage = 'too many login attempts\n'


def ClientSideKeyExchange(clientSocket, username: str) -> bool:
    myNonce = ExtraCode.GenerateNonce(myLocation)
    nonceMessage = username + "\t" + myNonce

    # Step 1, send first nonce
    encryptedNonce = ExtraCode.RSAEncrypt(thatLocation, nonceMessage.encode())
    clientSocket.send(encryptedNonce)

    # Step 2, receive first and second nonce
    nonceResponse = clientSocket.recv(1024)
    decryptedNonceResponse = (
        ExtraCode.RSADecrypt(myLocation, nonceResponse).decode("ascii"))

    firstNonce = decryptedNonceResponse.split('\t')[0]
    newNonce = decryptedNonceResponse.split('\t')[1]

    if firstNonce != myNonce:
        print('Reply nonce does not match what was sent')
        clientSocket.close()
        exit()

    # Step 3, send back second nonce
    encryptedReplyNonce = ExtraCode.RSAEncrypt(thatLocation, newNonce.encode())
    clientSocket.send(encryptedReplyNonce)

    clientSocket.recv(1024)

    # Step 4, send session key
    keyShare = ExtraCode.RSAEncrypt(thatLocation, SESSION_KEY)
    clientSocket.send(keyShare)

    return True


def ClientSideLogin(clientSocket, username, password) -> [bool, str]:

    loginSuccess = False

    # passwordHashed = (bcrypt.hashpw(bytes(password, 'utf-8')))
    passwordHashed = bcrypt.hashpw(bytes(password, 'ascii'), bcrypt.gensalt())

    # Encrypt password with AES
    SymEncryptedPassword = ExtraCode.SymEncrypt(SESSION_KEY, passwordHashed)

    # Encrypt password with RSA
    RSAEncryptedPassword = (
        ExtraCode.RSAEncrypt(thatLocation, SymEncryptedPassword))

    loginMessage = username + '\t' + RSAEncryptedPassword

    clientSocket.send(loginMessage)

    loginResponse = clientSocket.recv(1024)
    decryptedLoginResponse = (
        ExtraCode.RSADecrypt(myLocation, loginResponse).decode("ascii"))

    if decryptedLoginResponse == successMessage: loginSuccess = True

    return loginSuccess, decryptedLoginResponse


def ConnectToServer():

    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect(('localhost', 8089))
    print('server connection successful\n')

    username = 'painters'
    password = 'vp2aNk'

    if not ClientSideKeyExchange(clientSocket, username):
        clientSocket.close()
        exit()

    loginSuccess, loginStatus = False, ''

    while loginStatus != 'disconnect' and loginStatus != 'success':
        loginSuccess, loginStatus = (
            ClientSideLogin(clientSocket, username, password))

        print(loginStatus)

        username = input('username: ')
        password = input('password: ')

    if loginSuccess: print('Login Successful!')

    clientSocket.close()


if __name__ == "__main__":
    ConnectToServer()
