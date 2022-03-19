from abc import *
from ptCrypt.Symmetric.Cipher import Cipher


class BlockCipher(Cipher):

    
    @staticmethod
    @abstractmethod
    def getBlockSize():
        pass