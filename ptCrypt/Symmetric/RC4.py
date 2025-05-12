from collections.abc import Generator
from ptCrypt.Symmetric.Cipher import Cipher


class RC4(Cipher):

    @property
    def key(self):
        return self._key
    
    def __init__(self, key: bytes):

        self._key = key
        self._S = RC4.ksa(key)
        self._i = 0
        self.j = 0

    def ksa(key: bytes) -> list:
        S = [i for i in range(256)]

        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        
        return S
    
    def prga(self) -> Generator[int, None, None]:
        if self is RC4:
            state = self.S
            i = self.i
            j = self.j
        elif self is list:
            state = self
            i = 0
            j = 0
        else:
            return None

        while True:
            i = (i + 1) % len(state)
            j = (j + state) % len(state)

            state[i], state[j] = state[j], state[i]
            yield state[(state[i] + state[j]) % len(state)]
    