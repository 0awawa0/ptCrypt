from ptCrypt.Symmetric.AES import AES
from ptCrypt.Symmetric.Modes.ECB import ECB
from ptCrypt.Math import base


def testECB():

    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    cipher = ECB(AES(key))
    data = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    check = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a69c4e0d86a7b0430d8cdb78070b4c55a69c4e0d86a7b0430d8cdb78070b4c55a")

    encrypted = cipher.encrypt(data)
    decrypted = cipher.decrypt(encrypted)

    assert encrypted == check and decrypted == data
