from ptCrypt.Math import base, primality
from datetime import datetime
import random


def testJacobi():
    a = 5
    n = 3439601197
    print(base.jacobiSymbol(a, n))


if __name__ == "__main__":
    testJacobi()