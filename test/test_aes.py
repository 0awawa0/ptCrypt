from ptCrypt.Symmetric.AES import AES


def testSubBytes():

    data = [[i] for i in range(256)]
    AES.subBytes(data)
    i = 0
    for l in data:
        assert l[0] == AES.SBox[i]
        i += 1

    AES.invSubBytes(data)
    assert data == [[i] for i in range(256)]


def testShiftRows():
    state = [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 16]]
    check1 = [[1, 2, 3, 4], [6, 7, 8, 5], [11, 12, 9, 10], [16, 13, 14, 15]]
    check2 = [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 16]]

    AES.shiftRows(state)
    assert state == check1

    AES.invShiftRows(state)
    assert state == check2


def testMixColumns():
    state = [
        [0xd4, 0xe0, 0xb8, 0x1e],
        [0xbf, 0xb4, 0x41, 0x27],
        [0x5d, 0x52, 0x11, 0x98],
        [0x30, 0xae, 0xf1, 0xe5]
    ]

    check1 = [
        [0x04, 0xe0, 0x48, 0x28],
        [0x66, 0xcb, 0xf8, 0x06],
        [0x81, 0x19, 0xd3, 0x26],
        [0xe5, 0x9a, 0x7a, 0x4c]
    ]

    check2 = [
        [0xd4, 0xe0, 0xb8, 0x1e],
        [0xbf, 0xb4, 0x41, 0x27],
        [0x5d, 0x52, 0x11, 0x98],
        [0x30, 0xae, 0xf1, 0xe5]
    ]

    AES.mixColumns(state)
    assert state == check1

    AES.invMixColumns(state)
    assert state == check2


def testAddRoundKey():
    state = [
        [0x32, 0x88, 0x31, 0xe0],
        [0x43, 0x5a, 0x31, 0x37],
        [0xf6, 0x30, 0x98, 0x07],
        [0xa8, 0x8d, 0xa2, 0x34]
    ]

    key = b"\x2b\x28\xab\x09\x7e\xae\xf7\xcf\x15\xd2\x15\x4f\x16\xa6\x88\x3c"

    check = [
        [0x19, 0xa0, 0x9a, 0xe9],
        [0x3d, 0xf4, 0xc6, 0xf8],
        [0xe3, 0xe2, 0x8d, 0x48],
        [0xbe, 0x2b, 0x2a, 0x08]
    ]

    AES.addRoundKey(state, key)
    assert state == check