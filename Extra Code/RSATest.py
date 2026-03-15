def RSATest():

    p = 7
    q = 23
    n = p * q
    theta = (p - 1) * (q - 1)
    e = int(theta / 2) - ((theta % 2) + 1)

    k = 1
    d = 1.1
    while d - int(d) != 0.0:
        k += 1
        d = ((k * theta) + 1) / e
    d = int(d)

    print('k: ', k)
    print('e: ', e)
    print('d: ', d)
    print('n: ', n)

    M = 15

    print('plaintext: ', M)

    cipher = (M ^ e) % n
    print('ciphertext: ', cipher)

    plain = (cipher ^ int(d)) % n
    print('deciphered text:', plain)

if __name__ == "__main__":
    RSATest()
