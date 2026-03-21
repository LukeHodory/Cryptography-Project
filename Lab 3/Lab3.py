from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa


def GenerateKey():

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


def Encrypt(plainText, keyLength):

    with open('Public_Key' + str(keyLength) + '.pem', "rb") as key_file:
        publicKey = serialization.load_pem_public_key(key_file.read())

    ciphertext = publicKey.encrypt(plainText, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

    return ciphertext


def Decrypt(cipherText, keyLength):

    with open('Private_Key' + str(keyLength) + '.pem', "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None,)

    decryptedPlainText = private_key.decrypt(cipherText, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

    return decryptedPlainText


def main():

    # PLAINTEXT MESSAGE
    message = b"science compels us to explode the sun"
    cipherText = ''

    keyLength = 0
    keyFileCreated = False

    # MENU
    while True:
        print('\n'
              '1) Create Keys \n'
              '2) Encrypt using public key \n'
              '3) Decrypt using private key \n'
              '4) Exit')

        choice = int(input("Enter option: "))

        if choice == 1:
            keyLength = GenerateKey()
            keyFileCreated = True

        elif choice == 2:
        # elif choice == 2 and keyFileCreated:
            cipherText = Encrypt(message, keyLength)
            print(cipherText)
            with (open('EncryptedFile.txt', 'w')
                 as fw):
                fw.write(str(cipherText))

        elif choice == 3 and keyFileCreated and cipherText != '':
            decryptedPlainText = Decrypt(cipherText, keyLength)

            print(decryptedPlainText.decode())

        elif choice == 4: break
        elif not keyFileCreated: print('must first generate key')
        else: print('Enter valid option')


if __name__ == "__main__":
    main()
