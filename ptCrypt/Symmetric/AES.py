from ptCrypt.Symmetric.BlockCipher import BlockCipher


class AES(BlockCipher):

    blockSize = 16
    
    @property
    def key(self):
        return self._key
    
    def __init__(self, key: bytes):
        self._key = key
    
    def encrypt(self, data: bytes):
        return data
    
    def decrypt(self, data: bytes):
        return data
    
    def getBlockSize():
        return AES.blockSize