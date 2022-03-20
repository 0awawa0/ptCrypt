from ptCrypt.Symmetric.AES import AES


def testSubBytes():

    data = [i for i in range(256)]
    AES.subBytes(data)
    assert data == AES.SBox

    AES.invSubBytes(data)
    assert data == [i for i in range(256)]


def testShiftRows():
    state = [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 16]]
    check1 = [[1, 2, 3, 4], [6, 7, 8, 5], [11, 12, 9, 10], [16, 13, 14, 15]]
    check2 = [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 16]]

    AES.shiftRows(state)
    assert state == check1

    AES.invShiftRows(state)
    assert state == check2