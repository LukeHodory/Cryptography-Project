def analyseFrequency(plainText, keyword):
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
    analyseFrequency()