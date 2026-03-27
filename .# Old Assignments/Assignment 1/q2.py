def caesar_decode(encoded):
    alphabet = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                'u', 'v', 'w', 'x', 'y', 'z']
    cipherLength = len(encoded)
    numList = [0] * cipherLength

    # converts characters in cipher text to integers
    iter = 0
    for letter in encoded:
        index = 0
        for let in alphabet:
            if let == letter:
                numList[iter] = index
                break
            index += 1
        iter += 1

    # outputs cipher text with every possible offset
    for count in range(25):
        print("key:", count + 1)
        for num in numList:
            print(alphabet[(num + count) % 26], end="")
        print("\n")


def vigenere_encode(plainText, keyword):
    alphabet = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                'u', 'v', 'w', 'x', 'y', 'z']
    plainText = plainText.replace(' ', '')
    cipherLength = len(plainText)

    # create list of characters by repeating the keyword until correct length
    keyText = [''] * cipherLength
    keyTextIndex = 0
    for itemIndex in range(cipherLength):
        if keyTextIndex >= len(keyword):
            keyTextIndex = 0
        keyText[itemIndex] = keyword[keyTextIndex]
        keyTextIndex += 1

    # converts key text from characters to integers
    key = [0] * cipherLength
    keyIndex = 0
    for letter in keyText:
        index = 0
        for let in alphabet:
            if let == letter:
                key[keyIndex] = index
                break
            index += 1
        keyIndex += 1

    # converts plain text from characters to integers
    plainTextKey = [0] * cipherLength
    keyIndex = 0
    for letter in plainText:
        index = 0
        for let in alphabet:
            if let == letter:
                plainTextKey[keyIndex] = index
                break
            index += 1
        keyIndex += 1

    # creates cipher using corresponding integers in key and converted plain text
    cipherText = [''] * cipherLength
    for i in range(cipherLength):
        cipherText[i] = alphabet[(plainTextKey[i] + key[i] + 1) % 26]
    cipherText = ''.join(cipherText)

    print(cipherText)


if __name__ == '__main__':
    caesar_decode('ckswndwsgo')
    # vigenere_encode('spring is coming', 'song')


# See PyCharm help at https://www.jetbrains.com/help/pycharm/
