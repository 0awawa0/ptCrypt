from ptCrypt.Util.keys import IFC_APPROVED_LENGTHS
from ptCrypt.Asymmetric import RSA
from ptCrypt.Math.primality import millerRabin
from datetime import datetime


def testGenerateProvablePrimes():

    e = 65537
    N = 2048
    
    t = []
    for _ in range(10):
        start = datetime.now()
        seed = RSA.getSeed(N)
        res = None
        while not res:
            seed = RSA.getSeed(N)
            res = RSA.generateProvablePrimes(e, N, seed)
        t.append((datetime.now() - start).seconds)
        
        p, q = res
        assert millerRabin(p, 27) and millerRabin(q, 27)
    
    avg = sum(t) / len(t)
    print(avg)
    N = 3072
    
    t = []
    for _ in range(10):
        start = datetime.now()
        seed = RSA.getSeed(N)
        res = None
        while not res:
            seed = RSA.getSeed(N)
            res = RSA.generateProvablePrimes(e, N, seed)
        t.append((datetime.now() - start).seconds)

        p, q = res
        assert millerRabin(p, 27) and millerRabin(q, 27)
    
    avg = sum(t) / len(t)
    print(avg)
