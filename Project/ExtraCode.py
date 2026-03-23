import os
import bcrypt
import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509.verification import ClientVerifier

BLOCK_SIZE_BITS = 256


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


def GenerateNonce(thisLocation) -> str:
    return thisLocation + ' Nonce'


def GenerateRSAPair(thisLocation: str) -> None:
    # thisLocation = machine private key is for

    keyLength = 3072
    privateFile = thisLocation + '_Private_Key.pem'
    publicFile = thisLocation + '_Public_Key.pem'

    privateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=keyLength, )
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


def RSAEncrypt(thatLocation: str, plainText: bytes) -> bytes:
    fileName = thatLocation + '_Public_Key.pem'

    with open(fileName, "rb") as key_file:
        publicKey = serialization.load_pem_public_key(key_file.read())

    ciphertext = publicKey.encrypt(plainText, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

    return ciphertext


def RSADecrypt(thisLocation: str, cipherText: bytes) -> bytes:
    fileName = thisLocation + '_Private_Key.pem'

    with open(fileName, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None, )

    decryptedPlainText = private_key.decrypt(cipherText, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

    return decryptedPlainText


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


# TODO
def GenerateCertificate():

    # Generate our key
    newKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048)
    # Write our key to disk for safe keeping
    with open("path/to/store/key.pem", "wb") as f:
        f.write(newKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=
                serialization.BestAvailableEncryption(b"passphrase")))

    # Various details about who we are. For a self-signed certificate the
    # subject and issuer are always the same.
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com")])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        newKey.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.datetime.now(
            datetime.timezone.utc) + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False,
        # Sign our certificate with our private key
    ).sign(newKey, hashes.SHA256())

    # Write our certificate out to disk.
    with open("path/to/certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    ClientVerifier.verify(leaf=cert, intermediates=None)


# TODO
def ValidateCertificate():
    pass
