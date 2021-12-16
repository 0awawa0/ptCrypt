from ptCrypt.Util.keys import IFC_APPROVED_LENGTHS, millerRabinTestsForIFC
from ptCrypt.Asymmetric import RSA
from ptCrypt.Math.primality import millerRabin
from datetime import datetime


def testGenerateProvablePrimes():

    e = 65537
    N = 2048
    testsCount = millerRabinTestsForIFC(N)[0]
    
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
        assert millerRabin(p, testsCount) and millerRabin(q, testsCount)
    
    avg = sum(t) / len(t)
    print(avg)
    N = 3072
    testsCount = millerRabinTestsForIFC(N)[0]
    
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
        assert millerRabin(p, testsCount) and millerRabin(q, testsCount)
    
    avg = sum(t) / len(t)
    print(avg)


def testGenerateProbablePrimes():

    e = 65537
    N = 2048
    testsCount = millerRabinTestsForIFC(N)[0]
    print("Test count: ", testsCount)

    t = []
    for _ in range(10):
        start = datetime.now()
        res = RSA.generateProbablePrimes(e, N)
        assert res
        t.append((datetime.now() - start).seconds)
        
        p, q = res
        assert millerRabin(p, testsCount) and millerRabin(q, testsCount)
    
    avg = sum(t) / len(t)
    print(avg)
    N = 3072
    testsCount = millerRabinTestsForIFC(N)[0]
    print("Test count: ", testsCount)

    t = []
    for _ in range(10):
        start = datetime.now()
        res = RSA.generateProbablePrimes(e, N)
        assert res
        t.append((datetime.now() - start).seconds)

        p, q = res
        assert millerRabin(p, testsCount) and millerRabin(q, testsCount)
    
    avg = sum(t) / len(t)
    print(avg)


def testGenerateProvablePrimesWithConditions():

    e = 65537
    N = 1024
    testsCount = millerRabinTestsForIFC(N)[0]
    
    t = []
    for _ in range(10):
        start = datetime.now()
        seed = RSA.getSeed(N)
        res = None
        while not res:
            seed = RSA.getSeed(N)
            res = RSA.geneareteProvablePrimesWithConditions(e, N, seed)        
            t.append((datetime.now() - start).microseconds)
        
        p, q = res
        assert millerRabin(p, testsCount) and millerRabin(q, testsCount)
        
    avgTime = sum(t) / len(t)
    print(N, avgTime)

    e = 65537
    N = 2048
    testsCount = millerRabinTestsForIFC(N)[0]
    
    t = []
    for _ in range(10):
        start = datetime.now()
        seed = RSA.getSeed(N)
        res = None
        while not res:
            seed = RSA.getSeed(N)
            res = RSA.geneareteProvablePrimesWithConditions(e, N, seed)
        t.append((datetime.now() - start).seconds)
        
        p, q = res
        assert millerRabin(p, testsCount) and millerRabin(q, testsCount)
    
    avgTime = sum(t) / len(t)
    print(N, avgTime)

    e = 65537
    N = 3072
    testsCount = millerRabinTestsForIFC(N)[0]
    
    t = []
    for _ in range(10):
        start = datetime.now()
        seed = RSA.getSeed(N)
        res = None
        while not res:
            seed = RSA.getSeed(N)
            res = RSA.geneareteProvablePrimesWithConditions(e, N, seed)
        t.append((datetime.now() - start).seconds)
        
        p, q = res
        assert millerRabin(p, testsCount) and millerRabin(q, testsCount)
    avgTime = sum(t) / len(t)
    print(N, avgTime)
