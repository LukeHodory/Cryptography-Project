def GenerateKey():
    from cryptography.hazmat.primitives.asymmetric import rsa

    validLengths = 2048, 3072, 4096
    keyLength = int(input("Enter length of key (2048, 3072, or 4096): "))
    while keyLength not in validLengths:
        keyLength = int(input("Enter valid length of key: "))

    privateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=keyLength,
    )

    return privateKey, keyLength


def Encrypt(key, keyLength):
    if key == 0:
        print('Cannot encrypt without first generating key')
        return


def Decrypt(key, keyLength):
    if key == 0:
        print('Cannot decrypt without first generating key')
        return


def main():
    key = 0
    keyLength = 0
    while True:
        print('1) Create Keys \n'
              '2) Encrypt using public key \n'
              '3) Decrypt using private key \n'
              '4) Exit \n')

        choice = int(input("Enter choice: "))

        if choice == 1: key, keyLength = GenerateKey()
        elif choice == 2: Encrypt(key, keyLength)
        elif choice == 3: Decrypt(key, keyLength)
        elif choice == 4: break
        else: print('Enter valid choice')


if __name__ == "__main__":
    main()
