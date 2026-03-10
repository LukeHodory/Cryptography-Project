from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa


# TODO uncomment keyLength input,
#  delete explicit keyLength initialization
def GenerateKey():

    validLengths = 2048, 3072, 4096

    # keyLength = int(input("Enter length of key (2048, 3072, or 4096): "))
    keyLength = 2048

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


# TODO make sure everything is working here
def Encrypt(plainText, keyLength):

    with open('Public_Key' + str(keyLength) + '.pem', "rb") as key_file:
        publicKey = serialization.load_pem_public_key(key_file.read())

    ciphertext = publicKey.encrypt(plainText, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

    return ciphertext


# TODO finish Decrypt() method
def Decrypt(cipherText, keyLength):
    with open('key' + str(keyLength) + '.pem', "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    # plaintext = private_key.decrypt(
    #     ciphertext,
    #     padding.OAEP(
    #         mgf=padding.MGF1(algorithm=hashes.SHA256()),
    #         algorithm=hashes.SHA256(),
    #         label=None
    #     )
    # )

    plainText = ''
    return plainText


# TODO test report: screenshots to demonstrate your code can encrypt a
#  plaintext using the public key, and then decrypt it using the private key
#  to resume the same plaintext

def main():

    # PLAINTEXT MESSAGE
    message = b"encrypted data"
    cipherText = ''
    decryptedPlainText = ''

    keyLength = 0
    keyFileCreated = False
    while True:
        print('1) Create Keys \n'
              '2) Encrypt using public key \n'
              '3) Decrypt using private key \n'
              '4) Exit \n')

        choice = int(input("Enter option: "))

        if choice == 1:
            keyLength = GenerateKey()
            keyFileCreated = True

        elif choice == 2 and keyFileCreated:
            cipherText = Encrypt(message, keyLength)
            print(cipherText)

        elif choice == 3 and keyFileCreated and cipherText != '':
            decryptedPlainText = Decrypt(cipherText, keyLength)
            print(decryptedPlainText)

        elif choice == 4: break
        elif not keyFileCreated: print('must first generate key')
        else: print('Enter valid option')


if __name__ == "__main__":
    main()
