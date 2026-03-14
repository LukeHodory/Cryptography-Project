
def HashPasswords():
    with open('credentials.txt', 'r') as credentialsFile:
        loginFile = credentialsFile.read().split()
    loginInfo = [['' for x in range(2)] for y in range(50)]
    for i in range(100):
        loginInfo[int(i / 2)][i % 2] = loginFile[i]

    from cryptography.hazmat.primitives import hashes
    digest = hashes.Hash(hashes.SHA256())
    with open('hashedCredentials.txt', 'w') as hashedFile:
        for i in range(50):
            newDigest = digest.copy()
            newDigest.update(bytes(loginInfo[i][1], 'utf-8'))
            hashedFile.write(loginInfo[i][0] + ' ')
            hashedFile.write(str(newDigest.finalize()) + '\n')


def TestHashArray():
    with open('hashedCredentials.txt', 'r') as credentialsFile:
        loginFile = credentialsFile.read().split('\n')

    loginInfo = [['' for x in range(2)] for y in range(50)]
    for i in range(50):
        loginInfo[i][0] = loginFile[i].split(' ', 1)[0]
        loginInfo[i][1] = loginFile[i].split(' ', 1)[1]


if __name__ == "__main__":
    # HashPasswords()
    TestHashArray()


