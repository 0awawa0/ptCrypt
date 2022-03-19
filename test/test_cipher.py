from ptCrypt.Symmetric.AES import AES
from ptCrypt.Symmetric.BlockCipher import BlockCipher


def testCipherCreation():

    cipher = AES(b"1234")
    print(cipher.key)
    print(AES.getBlockSize())
    print(cipher.blockSize)
    print(cipher.encrypt(b"12345"))
    print(cipher.decrypt(b"54321"))
