def AnalyseFrequency():
    # [...[count, position of letter in alphabet]...]
    # list formed this way to allow sorting without losing data
    singleLetterCount = [[0, q] for q in range(26)]
    singleLetterFrequency = [[0.0, k] for k in range(26)]

    # [[first-letter...][second-letter...[count, first-letter, second-letter]...][...]]
    # [c, 1st, 2nd] -> stored as entry to 2d array
    # [x][_][_] first letter of pair
    # [_][y][_] second letter
    # also formed to allow sorting
    letterPairCount = [[[0, g, h] for h in range(26)] for g in range(26)]
    letterPairFrequency = [[[0.0, g, h] for h in range(26)] for g in range(26)]

    # upper case ascii alphabet, dec: 65 - 90
    # Read all words into a list of words
    with open('Luke.txt', 'r') as file:
        words = file.read().split()

    # fill both count lists
    for word in words:
        prevIndex = -1
        for letter in word:
            curIndex = ord(letter) - 65
            if 0 <= curIndex <= 25:
                singleLetterCount[curIndex][0] += 1
                if 0 <= prevIndex <= 25:
                    letterPairCount[prevIndex][curIndex][0] += 1
            prevIndex = curIndex

    totalSingle = 0
    for [count, _] in singleLetterCount: totalSingle += count

    totalPair = 0
    for entry in letterPairCount:
        for count, _, _ in entry: totalPair += count

    # convert letter counts to percentages
    for p in range(len(singleLetterCount)):
        unRounded = (singleLetterCount[p][0] / totalSingle) * 100
        singleLetterFrequency[p][0] = round(unRounded, 4)

    # percentage
    for p in range(len(letterPairCount)):
        for q in range(len(letterPairCount[p])):
            unRounded = (letterPairCount[p][q][0] / totalPair) * 100
            letterPairFrequency[p][q][0] = round(unRounded, 4)

    return (singleLetterCount, singleLetterFrequency, totalSingle,
            letterPairCount, letterPairFrequency, totalPair)


def CreateKeySingleLetter(singleLetterCount):
    plainTextFrequency = [['E', 12.0, 4], ['T', 9.10, 19], ['A', 8.12, 0], ['O', 7.68, 14],
                          ['I', 7.31, 8], ['N', 6.95, 13], ['S', 6.28, 18], ['R', 6.02, 17],
                          ['H', 5.92, 7], ['D', 4.32, 3], ['L', 3.98, 11], ['U', 2.88, 20],
                          ['C', 2.71, 2], ['M', 2.61, 12], ['F', 2.30, 5], ['Y', 2.11, 24],
                          ['W', 2.09, 22], ['G', 2.03, 6], ['P', 1.82, 15], ['B', 1.49, 1],
                          ['V', 1.11, 21], ['K', 0.69, 10], ['X', 0.17, 23], ['Q', 0.11, 16],
                          ['J', 0.10, 9], ['Z', 0.07, 25]]

    singleLetterCount.sort(key=lambda x: x[0])
    singleLetterCount.reverse()
    key = singleLetterCount

    # [...[plaintext letter, ciphertext letter]...]
    for i in range(len(key)): key[i][0] = plainTextFrequency[i][2]
    key.sort()
    singleLetterCount.sort(key=lambda x: x[1])

    # EditableKeyFile: can be edited by user
    with open('editable_key', 'w') as EditableKeyFile:
        for [num, _] in key: EditableKeyFile.write(str(num) + ' ')

    # KeyFile: file that will not be changed by user
    with open('single_letter_key', 'w') as KeyFile:
        for [num, _] in key: KeyFile.write(str(num) + ' ')


def CreateKeyLetterPair(letterPairCount):
    # [rank in ascending order...[first letter in pair, second letter]...]
    topPairsList = [[0, 0, 0] for _ in range(11)]

    # find top ten letter pairs
    for subList in letterPairCount:
        for entry in subList:
            # skip this entry if less than last entry in topPairs list
            for s in range(10):
                if entry[0] < topPairsList[9 - s][0]: break
                temp = topPairsList[9 - s]
                topPairsList[9 - s] = entry
                topPairsList[10 - s] = temp

    with open('letter_pair_key', 'w') as keyFile:
        for [_, first, second] in topPairsList:
            keyFile.write(str(first) + ' ')
            keyFile.write(str(second) + ' ')


def DecryptWithSingleLetterKey(file):
    with open(file, 'r') as keyFile:
        keyCharacters = keyFile.read().split()

    key = [0] * 26
    for k in range(len(keyCharacters)):
        key[k] = int(keyCharacters[k])

    with open('Luke.txt', 'r') as encryptedFile:
        encryptedText = encryptedFile.readlines()

    fileName = file + '_results'
    with open(fileName, 'w') as decryptedFile:
        m = 0
        for phrase in encryptedText:
            n = 0
            for letter in phrase:
                if 65 <= ord(letter) <= 90:
                    keyIndex = ord(letter) - 65
                    swap = chr(key[keyIndex] + 65)
                    decryptedFile.write(swap)
                else:
                    decryptedFile.write(letter)
                    n += 1
                m += 0


def DecryptWithLetterPairKey():
    pass
    # plainTextTopPairs = [[19, 7], [7, 4], [8, 13], [4, 13], [13, 19],
    #                      [17, 4], [4, 17], [0, 13], [19, 8], [4, 18]]
    #
    # with open('letter_pair_key', 'r') as keyFile:
    #     keyCharacters = keyFile.read().split()
    # keyFile.close()
    #
    # key = [0] * 26
    # for k in range(len(keyCharacters)):
    #     key[k] = int(keyCharacters[k])
    #
    # with open('Luke.txt', 'r') as encryptedFile:
    #     encryptedText = encryptedFile.readlines()
    #
    # with open('letter_pair_key_results', 'w') as decryptedFile:
    #     m = 0
    #     for phrase in encryptedText:
    #         n = 0
    #         for letter in phrase:
    #             if 65 <= ord(letter) <= 90:
    #                 keyIndex = ord(letter) - 65
    #                 swap = chr(key[keyIndex] + 65)
    #                 decryptedFile.write(swap)
    #             else:
    #                 decryptedFile.write(letter)
    #                 n += 1
    #             m += 0


def EditKey():
    KeyIntoString('editable_key',
                  'editable_key_string')

    for iter in range(10):
        with open('editable_key', 'r') as numFile:
            keyNums = numFile.read().split()

        with open('editable_key_string', 'r') as stringFile:
            keyCharacters = stringFile.read().split()

        key = [0] * 26
        for k in range(len(keyNums)): key[k] = int(keyNums[k])

        print(keyCharacters)
        print("swap which letters?: ")
        selection1 = input()
        selection2 = input()

        selection1 = ord(selection1) - 65
        selection2 = ord(selection2) - 65

        firstIndex = 0
        secondIndex = 0
        while key[firstIndex] != selection1: firstIndex += 1
        while key[secondIndex] != selection2: secondIndex += 1

        temp = key[firstIndex]
        key[firstIndex] = key[secondIndex]
        key[secondIndex] = temp

        with open('editable_key', 'w') as KeyFile:
            for num in key:
                KeyFile.write(str(num) + ' ')

        KeyIntoString('editable_key',
                      'editable_key_string')
        DecryptWithSingleLetterKey('editable_key')


def KeyIntoString(inFile, outFile):
    with open(inFile, 'r') as keyFile:
        keyCharacters = keyFile.read().split()

    key = [0] * 26
    for k in range(len(keyCharacters)): key[k] = int(keyCharacters[k])

    with open(outFile, 'w') as keyFileString:
        for item in key: keyFileString.write(chr(item + 65))


if __name__ == '__main__':
    (oneCount, oneFreq, oneTotal,
        twoCount, twoFreq, twoTotal) = AnalyseFrequency()

    CreateKeySingleLetter(oneCount)
    DecryptWithSingleLetterKey('final_key')
    KeyIntoString('single_letter_key',
                  'single_letter_key_string')

    # CreateKeyLetterPair(twoCount)
    # DecryptWithLetterPairKey()

    # EditKey()
