from ptCrypt.Math import base, primality
from datetime import datetime
import random


def measurePrimalityTestTime():
    t = []
    t1 = []
    count = 0
    for _ in range(10):
        prime = random.getrandbits(2048)

        start = datetime.now()
        a = base.isPrime(prime, 10)
        end = datetime.now()
        t.append((end - start).microseconds)

        start = datetime.now()
        b = base.isPrimeOld(prime, 10)
        end = datetime.now()
        t1.append((end - start).microseconds)

        assert a == b
        if a:
            count += 1


    avg = sum(t) / len(t)
    avg1 = sum(t1) / len(t1)
    print(f"Avg time: {avg}")
    print(f"Avg time: {avg1}")
    print(f"Enhance: {avg1 / avg}")
    print(f"Count of primes: {count}")


def testLucas():

    count = 0
    ms = []
    ls = []
    p = base.getPrime(128)
    while count < 100:
        a = random.getrandbits(128)
        start = datetime.now()
        m = base.millerRabin(a, 10)
        end = datetime.now()
        ms.append((end - start).microseconds)

        start = datetime.now()
        l = base.lucasTest(a)
        end = datetime.now()
        ls.append((end - start).microseconds)

        if m:
            count += 1
            # print(m)
            # print(l)

    avg = sum(ms) / len(ms)
    avg1 = sum(ls) / len(ls)
    print(avg)
    print(avg1)
    print(count)


def testShaweTaylor():

    length = 1024

    t = []
    t1 = []
    for i in range(10):
        start = datetime.now()
        q = primality.getPrime(length)
        end = datetime.now()
        t.append((end - start).microseconds)

        start = datetime.now()
        p = primality.shaweTaylorRandomPrime(length, random.getrandbits(length - 1))
        while not p["status"]:
            p = primality.shaweTaylorRandomPrime(length, random.getrandbits(length - 1))
        end = datetime.now()
        t1.append((end - start).microseconds)

        assert primality.millerRabin(p["prime"], 64)
    
    avg = sum(t) / len(t)
    avg1 = sum(t1) / len(t1)
    print(f"Avg: {avg} microseconds")
    print(f"Avg1: {avg1} microseconds")


if __name__ == "__main__":
    testShaweTaylor()