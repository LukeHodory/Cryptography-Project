from socket import *
from Project import ExtraCode as EX

myLocation = 'Server'
thatLocation = 'Client'

badUsername = 'User name does not exist\n'
badPassword = 'Incorrect password\n'
tooManyAttempts = 'too many login attempts\n'
successMessage = 'Login Successful\n'


def PutCredsInArray() -> list[list[str]]:
    # Read in creds from file into array

    with open('HashedCreds.txt', 'r') as credentialsFile:
        credentials = credentialsFile.read().split('\n')
    creds = [['' for _ in range(3)] for _ in range(50)]
    for i in range(50):
        creds[i][0] = credentials[i].split(' ', 2)[0]
        creds[i][1] = credentials[i].split(' ', 2)[1]
        creds[i][2] = credentials[i].split(' ', 2)[2]

    return creds


def CheckCreds(creds: list[list[str]], username: str, password: str) -> [bool, bool]:
    
    # Find index of username, if it exists
    goodUsername = False
    usernameIndex = 0
    for i in range(len(creds)):
        if username == creds[i][0]: break
        usernameIndex += 1

    # if final username index is less than length of creds
    #    username was found
    if usernameIndex < len(creds): goodUsername = True

    # Check password associated with username
    goodPassword = False
    if goodUsername: goodPassword = password == creds[usernameIndex][1]

    return goodUsername, goodPassword


def ServerSideKeyExchange(serverSocket, firstNonce: str) -> bytes:
    newNonce = EX.GenerateNonce(myLocation)
    nonceReply = firstNonce + "\t" + newNonce

    # Step 2, send first and second nonce
    encryptedReply = EX.RSAEncrypt(thatLocation, nonceReply.encode())
    serverSocket.send(encryptedReply)

    # Step 3, receive back second nonce
    nonceResponse = serverSocket.recv(1024)
    decryptedNonceResponse = EX.RSADecrypt(myLocation, nonceResponse).decode("ascii")
    
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
    sessionKey = EX.RSADecrypt(myLocation, encryptedKey)

    return sessionKey


def ServerSideLogin(serverSocket, sessionKey: bytes, username: str, password: str) -> bool:
    
    creds = PutCredsInArray()
    loginAttempts = 1
    maxAttempts = 5
    
    goodUsername, goodPassword = CheckCreds(creds, username, password)
    
    loginStatus = ''
    
    while loginAttempts < maxAttempts:
        
        if not goodPassword: loginStatus = badPassword
        if not goodUsername: loginStatus = badUsername
        if goodUsername and goodPassword: return True

        encryptedReply = EX.RSAEncrypt(thatLocation, loginStatus.encode())
        serverSocket.send(encryptedReply)

        credsResponse = serverSocket.recv(1024)
        RSADecryptedCreds = EX.RSADecrypt(myLocation, credsResponse)
        newUsername = RSADecryptedCreds.split('\t')[0].decode("ascii")
        
        symEncryptedPassword = RSADecryptedCreds.split('\t')[1]
        newPassword = EX.SymDecrypt(sessionKey, symEncryptedPassword).decode('ascii')

        goodUsername, goodPassword = CheckCreds(creds, newUsername, newPassword)
        loginAttempts += 1
        
    return False
        

def ConnectToClient():

    # Create Socket
    newSocket = socket(AF_INET, SOCK_STREAM)
    newSocket.bind(('localhost', 8089))
    newSocket.listen(1)
    print("The server is ready to receive requests")
    serverSocket, addr = newSocket.accept()

    # Step 1, receive first nonce
    encryptedRequest = serverSocket.recv(1024)
    keyExchangeInfo = EX.RSADecrypt(myLocation, encryptedRequest).decode("ascii")
    clientNonce = keyExchangeInfo.split('\t')[1]

    sessionKey = ServerSideKeyExchange(serverSocket, clientNonce)
    username = keyExchangeInfo.split('\t')[0]

    encryptedCredsMessage = serverSocket.recv(1024)

    decryptedCreds = EX.SymDecrypt(sessionKey, encryptedCredsMessage).decode("ascii")

    decryptedPassword = decryptedCreds.split('\t')[1]

    loginReply = tooManyAttempts
    if ServerSideLogin(serverSocket, sessionKey, username, decryptedPassword):
        loginReply = successMessage

    encryptedReply = EX.RSAEncrypt(thatLocation, loginReply.encode())
    serverSocket.send(encryptedReply)
    serverSocket.close()


if __name__ == "__main__":
    ConnectToClient()
