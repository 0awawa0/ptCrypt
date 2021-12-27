from ptCrypt.Math import base, primality
from datetime import datetime
import random


def testJacobi():
    a = 5
    n = 3439601197
    print(base.jacobiSymbol(a, n))


def testPartition():

    cases = [
        (b"\x00", 1),
        (b"\x00", 2),
        (b"\x00\x01", 1),
        (b"\x00\x01", 2),
        (b"\x00\x01\x02\x03\x04", 2)
    ]

    checks = [
        [b"\x00"],
        [b"\x00"],
        [b"\x00", b"\x01"],
        [b"\x00\x01"],
        [b"\x00\x01", b"\x02\x03", b"\x04"]
    ]

    for i in range(len(cases)):
        test = cases[i]
        result = base.partition(test[0], test[1])
        assert result == checks[i]


def testIntToBytes():

    cases = [
        (0x01, 2, "big"),
        (0x0102, 2, "big"),
        (0x0102, 1, "big"),
        (0x01, 2, "little"),
        (0x0102, 2, "little"),
        (0x0102, 1, "little")
    ]

    checks = [
        b"\x00\x01",
        b"\x01\x02",
        b"\x01\x02",
        b"\x01\x00",
        b"\x02\x01",
        b"\x02\x01"
    ]

    for i in range(len(cases)):
        value, size, byteorder = cases[i]
        result = base.intToBytes(value, size, byteorder)
        assert result == checks[i]
