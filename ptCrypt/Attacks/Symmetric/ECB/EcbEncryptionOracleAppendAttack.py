"""Encryption oracle attack on the ECB encryption mode. 
Applicable when you have an oracle that allows you to encrypt arbitrary text and appends secret information to your message.
Let's call secret part 'x', then this attack would be applicable if you can send value 'y' and oracle actually encrypts value 'yx' and sends
encrypted text back to you.

Then you can ecnrypt different values of 'y' in such a way that you can infer 'x' byte by byte.

There are two required parameters:

1) blockSize - it is a block size of the underlying cipher used by the oracle. 16 for AES.
2) query - a function that receives arbitrary bytes, sends them to the oracle to encrypt and returns encrypted bytes. It is your responsibility to 
implement communication with the oracle.

Optional parameters are:

1) listener - implementation of the Listener interface. You should pass that if you want to listen to attack updates, such as when attack starts and finishes, 
    when next byte is found or when a failure occurs
2) searchStart - value from which to start searching byte. By default it is 0, but if you have additional knowledge about the secret, you can set differnet value
    to optimize the search. For example, if you known that the secret consists of printable ASCII characters, then you should set searchStart to 32.
3) searchEnd - same as searchStart but from the other side. If the secret consists of printable ASCII characters, then you can set 127
4) knownPlaintext - known part of the secret. Note that this must be first N bytes of the secret, not any arbitrary part
"""
class EcbEncryptionOracleAppendAttack:

    class Listener:
        def attackStarted(self):
            pass

        def foundValue(self, position: int, value: int, totalCount: int):
            pass

        def attackFinished(self, foundText: bytes):
            pass

        def failedToFind(self, position: int):
            pass

    def __init__(
        self, 
        blockSize: int, 
        query: callable, 
        listener: Listener = None, 
        searchStart: int = 0, 
        searchEnd: int = 256,
        knownText: bytes = b""
    ):
        self.blockSize = blockSize
        self.query = query
        self.knownPlaintext = knownText
        self.listener = listener 
        self.searchStart = searchStart
        self.searchEnd = searchEnd


    def run(self):

        self.totalLength = self.__determineTotalLength()
        self.blocksCount = self.totalLength // self.blockSize

        if self.listener: self.listener.attackStarted()

        while len(self.knownPlaintext) < self.totalLength:
            foundByte = self.__searchByte()

            if foundByte:
                self.knownPlaintext += bytes([foundByte])
                if self.listener: self.listener.foundValue(len(self.knownPlaintext), foundByte, self.totalLength)
            else:
                if self.listener: self.listener.failedToFind(len(self.knownPlaintext))
                return self.knownPlaintext
        
        if self.listener: self.listener.attackFinished(self.knownPlaintext)

        return self.knownPlaintext


    def __searchByte(self):
        target = self.__sliceInterestingBlock(self.query(b"\00" * self.__getZerosCount()))

        for candidate in range(self.searchStart, self.searchEnd):
            payload = self.__preparePayloadWithCandidate(candidate)
            ciphertext = self.__sliceInterestingBlock(self.query(payload))

            if target == ciphertext: return candidate
        return None


    def __determineTotalLength(self):
        payload = b"\00"
        encrypted = self.query(payload)
        return len(encrypted)


    def __sliceInterestingBlock(self, text: bytes) -> bytes:
        return text[(self.blocksCount - 1) * self.blockSize: self.blocksCount * self.blockSize]


    def __preparePayloadWithCandidate(self, candidate: int) -> bytes:
        return b"\00" * self.__getZerosCount() + self.knownPlaintext + bytes([candidate])


    def __getZerosCount(self) -> int:
        return self.totalLength - len(self.knownPlaintext) - 1