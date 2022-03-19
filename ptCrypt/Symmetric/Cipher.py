from abc import *


class Cipher(ABC):

    @abstractproperty
    def key(self):
        pass

    @abstractmethod
    def __init__(self, key: bytes):
        pass
    
    @abstractmethod
    def encrypt(self, data: bytes):
        pass

    @abstractmethod
    def decrypt(self, data: bytes):
        pass