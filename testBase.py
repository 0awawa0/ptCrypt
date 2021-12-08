from Math import base, primality
from datetime import datetime
import random
from Math.primality import millerRabin, primeFactors, shaweTaylorRandomPrime


def testJacobi():
    a = 5
    n = 3439601197
    print(base.jacobiSymbol(a, n))


if __name__ == "__main__":
    testJacobi()