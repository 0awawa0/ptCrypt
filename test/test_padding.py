from ptCrypt.Math.base import pad
from ptCrypt.Symmetric.Paddings.ZeroPadding import ZeroPadding
from ptCrypt.Symmetric.Paddings.PKCS5Padding import PKCS5Padding


def testZeroPadding():
    data = b"\x11\x12\x13"
    padding = ZeroPadding(4)
    assert padding.pad(data) == b"\x11\x12\x13\x00"
    assert padding.unpad(padding.unpad(data)) == data


def testPKCS5Padding():
    data = b"\x11\x22\x33"
    padding = PKCS5Padding(4)
    assert padding.pad(data) == b"\x11\x22\x33\x01"
    assert padding.unpad(padding.pad(data)) == data

    data = b"\x11\x22\x33\x44"
    padding = PKCS5Padding(4)
    assert padding.pad(data) == b"\x11\x22\x33\x44\x04\x04\x04\x04"
    assert padding.unpad(padding.pad(data)) == data