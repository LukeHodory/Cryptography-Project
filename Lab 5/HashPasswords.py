import time
from cryptography.hazmat.primitives import hashes
import bcrypt

def HashCredentials():
    with open('credentials.txt', 'r') as credentialsFile:
        loginFile = credentialsFile.read().split()

    loginInfo = [['' for x in range(2)] for y in range(50)]
    for i in range(100):
        loginInfo[int(i / 2)][i % 2] = loginFile[i]

    digest = hashes.Hash(hashes.SHA256())
    with open('HashedCredentials.txt', 'w') as hashedFile:
        for i in range(50):
            newDigest = digest.copy()
            newDigest.update(bytes(loginInfo[i][1], 'utf-8'))
            hashedFile.write(loginInfo[i][0] + ' ')
            hashedFile.write(str(newDigest.finalize()) + '\n')


def BigHashPasswords():
    start = time.time()

    with open('top-1million-password-list.txt', 'r') as credentialsFile:
        topPasswords = credentialsFile.read().split()

    digest = hashes.Hash(hashes.SHA256())
    with open('BigHashedPasswords.txt', 'w') as hashedFile:
        for element in topPasswords:
            newDigest = digest.copy()
            newDigest.update(bytes(element, 'utf-8'))
            hashedFile.write(str(newDigest.finalize()) + '\n')

    end = time.time()
    length = end - start
    print(length, "seconds")


def TestBigPasswords():
    start = time.time()

    with open('BigHashedPasswords.txt', 'r') as topPasswordsFile:
        topPasswords = topPasswordsFile.read().split()

    with open('HashedCredentials.txt', 'r') as credentialsFile:
        credentials = credentialsFile.read().split('\n')

    loginInfo = [['' for _ in range(2)] for _ in range(50)]
    for i in range(50):
        loginInfo[i][0] = credentials[i].split(' ', 1)[0]
        loginInfo[i][1] = credentials[i].split(' ', 1)[1]

    foundPasswords = []
    for testPassword in topPasswords:
        for myPassword in loginInfo:
            if testPassword == myPassword[1]:
                foundPasswords.append(myPassword[0])

    print(foundPasswords)

    end = time.time()
    length = end - start
    print(length, "seconds")


def TestHashArray():
    with open('HashedCredentials.txt', 'r') as credentialsFile:
        loginFile = credentialsFile.read().split('\n')

    loginInfo = [['' for x in range(2)] for y in range(50)]
    for i in range(50):
        loginInfo[i][0] = loginFile[i].split(' ', 1)[0]
        loginInfo[i][1] = loginFile[i].split(' ', 1)[1]


def TestBcrypt():
    password = b"super secret password"
    # Hash a password for the first time, with a randomly-generated salt
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())
    # Check that an unhashed password matches one that has previously been
    # hashed
    if bcrypt.checkpw(password, hashed): print("It Matches!")
    else: print("It Does not Match :(")


if __name__ == "__main__":
    # HashPasswords()
    # TestHashArray()
    # BigHashPasswords()
    # TestBigPasswords()
    TestBcrypt()


