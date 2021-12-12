from ptCrypt.Asymmetric.ECC import Curve
import Math.base as base
import random
from datetime import datetime


def factor(n, bound=100, timeout=None):

    start = datetime.now()
    curvesCount = 0
    k = 1
    for prime in base.SMALL_PRIMES[:bound]:
        k *= prime

    T = None
    while 1:
        curvesCount += 1
        if timeout and (datetime.now() - start).seconds > timeout:
            return None

        a = random.randint(2, n - 1)
        b = random.randint(2, n - 1)
        A = random.randint(2, n - 1)

        B = (pow(b, 2, n) - pow(a, 3, n) - A * a) % n
        g = base.gcd(4 * pow(A, 3) + 27 * pow(B, 2), n)
        if g > 1 and g < n:
            return g

        curve = Curve(A, B, n)
        P = curve.point(a, b)
        if curve.hasSingularPoints():
            continue
        print(curvesCount)

        for i in range(2, bound):
            Q = i * P
            if type(Q) is int:
                if Q < n:
                    return Q
                break
            P = Q

        bound += 1
