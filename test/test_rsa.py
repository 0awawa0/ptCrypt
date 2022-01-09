from hashlib import sha256
import os
import random
from ptCrypt.Math import base
from ptCrypt.Util.keys import IFC_APPROVED_LENGTHS, millerRabinTestsForIFC, getIFCSecurityLevel, getIFCAuxiliaryPrimesLegths
from ptCrypt.Asymmetric import RSA
from ptCrypt.Math.primality import millerRabin, shaweTaylor
from datetime import date, datetime


def testGenerateProvablePrimes():
    print("testGenerateProvablePrimes")

    e = 65537
    N = 2048
    testsCount = millerRabinTestsForIFC(N)[0]
    
    t = []
    for _ in range(1):
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
    for _ in range(1):
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
    print("testGenerateProbablePrimes")

    e = 65537
    N = 2048
    testsCount = millerRabinTestsForIFC(N)[0]
    print("Test count: ", testsCount)

    t = []
    for _ in range(1):
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
    for _ in range(1):
        start = datetime.now()
        res = RSA.generateProbablePrimes(e, N)
        assert res
        t.append((datetime.now() - start).seconds)

        p, q = res
        assert millerRabin(p, testsCount) and millerRabin(q, testsCount)
    
    avg = sum(t) / len(t)
    print(avg)


def testGenerateProvablePrimesWithConditions():
    print("testGenerateProvablePrimesWithConditions")

    e = 65537
    N = 1024
    testsCount = millerRabinTestsForIFC(N)[0]
    
    t = []
    for _ in range(1):
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
    for _ in range(1):
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
    for _ in range(1):
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
    print("testGenerateProbablePrimesWithAuxiliaryPrimes")

    e = 65537

    for N in IFC_APPROVED_LENGTHS[:3]:
        testsCount = millerRabinTestsForIFC(N, False)[0]
        t = []
        p1Len, p2Len = getIFCAuxiliaryPrimesLegths(N, probablePrimes=False)
        for _ in range(1):
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
    print("testGenerateProbablePrimesWithConditions")

    e = 65537
    for N in IFC_APPROVED_LENGTHS[0:3]:

        testsCount = millerRabinTestsForIFC(N)[0]
        for _ in range(1):
            while True:
                seed = RSA.getSeed(N)
                res = RSA.generateProbablePrimesWithConditions(e, N, seed, probablePrimes = False)
                if not res: continue

                p, q = res

                assert millerRabin(p, testsCount) and millerRabin(q, testsCount)
                break

    for N in IFC_APPROVED_LENGTHS[0:3]:

        testsCount = millerRabinTestsForIFC(N)[0]
        for _ in range(1):
            while True:
                res = RSA.generateProbablePrimesWithConditions(e, N, None, probablePrimes = True)
                if not res: continue

                p, q = res

                assert millerRabin(p, testsCount) and millerRabin(q, testsCount)
                break


def testOAEPEncryptionAndDecryption():
    print("testOAEPEncryptionAndDecryption")

    e = 65537

    for N in IFC_APPROVED_LENGTHS[:1]:
        print(N)

        for _ in range(100):
            res = None
            while res == None:
                seed = RSA.getSeed(N)
                res = RSA.generateProbablePrimesWithConditions(e, N, seed)
    
            p, q = res
            n = p * q
            d = pow(e, -1, (p - 1) * (q - 1))
    
            maxLength = base.byteLength(n) - 2 * sha256().digest_size - 2
            m = os.urandom(maxLength)
            c = RSA.oaepEncrypt(e, n, m)
            m_ = RSA.oaepDecrypt(d, n, c)
            if m != m_:
                print(m)


def testPKCS1V15EncryptionAndDecryption():
    print("testPkcs1V15EncryptionAndDecryption")

    e = 65537
    for N in IFC_APPROVED_LENGTHS[:1]:
        
        for _ in range(100):
            res = None
            while res == None:
                seed = RSA.getSeed(N)
                res = RSA.generateProbablePrimesWithConditions(e, N, seed)
        
            p, q = res
            n = p * q
            d = pow(e, -1, (p - 1) * (q - 1))

            maxLength = base.byteLength(n) - 11
            m = os.urandom(maxLength)
            c = RSA.pkcs1v15Encrypt(e, n, m)
            m_ = RSA.pkcs1v15Decrypt(d, n, c)
            if m != m_:
                print(m_)
                print(m)


def testEMSAPSSEncodeAndVerify():
    print("testEMSA-PSSEncodeAndVerify")

    for _ in range(100):
        message = base.getRandomBytes(100)
        em = RSA.emsaPssEncode(message, len(message) * 128, 16)
        assert em != None
        assert RSA.emsaPssVerify(message, em, len(message) * 128, 16)