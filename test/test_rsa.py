from ptCrypt.Util.keys import IFC_APPROVED_LENGTHS, millerRabinTestsForIFC, getIFCSecurityLevel, getIFCAuxiliaryPrimesLegths
from ptCrypt.Asymmetric import RSA
from ptCrypt.Math.primality import millerRabin, shaweTaylor
from datetime import date, datetime


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


def testGenerateProbablePrimesWithAuxiliaryPrimes():
    e = 65537

    for N in IFC_APPROVED_LENGTHS[:3]:
        testsCount = millerRabinTestsForIFC(N, False)[0]
        t = []
        p1Len, p2Len = getIFCAuxiliaryPrimesLegths(N, probablePrimes=False)
        for _ in range(10):
            while True:
                start = datetime.now()
                seed = RSA.getSeed(N)
                res = shaweTaylor(p1Len, seed)
                if not res["status"]: continue
                p1 = res["prime"]
                primeSeed = res["primeSeed"]

                res = shaweTaylor(p2Len, primeSeed)
                if not res["status"]: continue

                p2 = res["prime"]
                primeSeed = res["primeSeed"]

                p = RSA.generateProbablePrimeWithAuxiliaryPrimes(p1, p2, N, e)
                if not p: continue
                end = datetime.now()
                t.append((end - start).microseconds / 1000)

                assert millerRabin(p[0], testsCount)
                break
        avg = sum(t) / len(t)
        print(N, avg)


def testGenerateProbablePrimesWithConditions():

    e = 65537
    for N in IFC_APPROVED_LENGTHS[0:3]:

        testsCount = millerRabinTestsForIFC(N)[0]
        for _ in range(10):
            while True:
                seed = RSA.getSeed(N)
                res = RSA.generateProbablePrimesWithConditions(e, N, seed, probablePrimes = False)
                if not res: continue

                p, q = res

                assert millerRabin(p, testsCount) and millerRabin(q, testsCount)
                break

    for N in IFC_APPROVED_LENGTHS[0:3]:

        testsCount = millerRabinTestsForIFC(N)[0]
        for _ in range(10):
            while True:
                res = RSA.generateProbablePrimesWithConditions(e, N, None, probablePrimes = True)
                if not res: continue

                p, q = res

                assert millerRabin(p, testsCount) and millerRabin(q, testsCount)
                break