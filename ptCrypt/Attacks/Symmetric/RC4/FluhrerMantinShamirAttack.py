from abc import abstractmethod

"""Fluhrer-Mantin-Shamir attack on the RC4 encryption.
For an attack to be applicable 2 requirements must be satisfied:

1) There is a known IV at least 3 bytes long prepended to the key before the encryption.
This IV might either be chosen by the attacker, or can be determined from an encryption process.

2) Attacker can determine the first keystream byte. So an attacker either can choose a plaintext to
encrypt and can calculate the first keystream byte from plaintext and ciphertext, or can guess first 
plaintext byte.

For more information about the weakness and the attack see the original paper: https://www.cs.cornell.edu/people/egs/615/rc4_ksaproc.pdf
"""
class FluhrerMantinShamirAttack:

    class Callback:

        """Called when attack has prepared a new nonce to try.
        nonce is passed as a hex string. Callback must return the 
        first keystream byte generated from RC4 
        calculated after using passed nonce.
        """
        @abstractmethod
        def applyNonce(self, nonce: str) -> int:
            pass

        """Called after attack has determined a key byte corresponding
        to the nonces it provided. keyByt is passed as an integer.
        """
        @abstractmethod
        def onKeyByteFound(self, keyByte: int):
            pass

        """Called to check if the attack should continue running.
        If enough key bytes has been calculated, callback should return False.
        """
        @abstractmethod
        def shouldContinue(self):
            pass

        """Called after attack has stopped. Attack provides all key bytes calculated so far as a bytes stream.
        """
        @abstractmethod
        def onFinished(self, key: bytes):
            pass


    def __init__(self, callback: Callback, knownKey: bytes = b""):
        self.knownKey = knownKey
        self.callback = callback

    def run(self):

        while True:
            candidates = dict()

            for X in range(256):

                IV = bytes([len(self.knownKey) + 3, 255, X])
                nonce = IV.hex()

                keyStreamByte = self.callback.applyNonce(nonce)

                (i, j, S) = FluhrerMantinShamirAttack.reducedKSA(IV + self.knownKey)
                keyByteCandidate = (keyStreamByte - j - S[i]) % 256

                if keyByteCandidate in candidates:
                    candidates[keyByteCandidate] = candidates[keyByteCandidate] + 1
                else:
                    candidates[keyByteCandidate] = 1
            
            maxCount = 0
            maxValue = 0
            for k in candidates:
                if candidates[k] > maxCount:
                    maxCount = candidates[k]
                    maxValue = k
            
            self.knownKey += bytes([maxValue])

            self.callback.onKeyByteFound(maxValue)

            if not self.callback.shouldContinue():
                break
        
        self.callback.onFinished(self.knownKey)

    def reducedKSA(knownKey: bytes):
        S = [i for i in range(256)]

        j = 0
        for i in range(len(knownKey)):
            j = (j + S[i] + knownKey[i % len(knownKey)]) % 256
            S[i], S[j] = S[j], S[i]
    
        i += 1

        return (i, j, S)

