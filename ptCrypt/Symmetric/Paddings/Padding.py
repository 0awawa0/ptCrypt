from abc import *


class Padding(ABC):

    @abstractmethod
    def __init__(self):
        pass
    
    @abstractmethod
    def pad(self, data: bytes) -> bytes:
        pass
    
    @abstractmethod
    def unpad(self, data: bytes) -> bytes:
        pass