from ptCrypt.Math.base import pad
from ptCrypt.Symmetric.Paddings.ZeroPadding import ZeroPadding


def testZeroPadding():
    data = b"\x11\x12\x13"
    padding = ZeroPadding(4)
    assert padding.pad(data) == b"\x11\x12\x13\x00"
    assert padding.unpad(padding.unpad(data)) == data