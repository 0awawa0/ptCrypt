from ptCrypt.Symmetric.AES import AES
from ptCrypt.Symmetric.Modes.ECB import ECB
from ptCrypt.Symmetric.Modes.CBC import CBC
from ptCrypt.Math import base


def testECB():

    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    cipher = ECB(AES(key))
    data = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    check = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a69c4e0d86a7b0430d8cdb78070b4c55a69c4e0d86a7b0430d8cdb78070b4c55a")

    encrypted = cipher.encrypt(data)
    decrypted = cipher.decrypt(encrypted)

    assert encrypted == check and decrypted == data


def testCBC():
    
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    data = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    check = bytes.fromhex("76d0627da1d290436e21a4af7fca94b732a06af3e0df74a359a0d1f48889e61526e58cb3edca4ac1c4ab097eecba37fc")

    cipher = CBC(AES(key), iv)
    encrypted = cipher.encrypt(data)
    decrypted = cipher.decrypt(encrypted)

    print(encrypted.hex())
    assert encrypted.hex() == check.hex()
    assert decrypted.hex() == data.hex()
