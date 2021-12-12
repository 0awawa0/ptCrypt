from ptCrypt.Math import primality
from datetime import datetime
import random


def measurePrimalityTestTime():
    t = []
    t1 = []
    count = 0
    for _ in range(10):
        prime = random.getrandbits(2048)

        start = datetime.now()
        a = primality.millerRabin(prime, 10)
        end = datetime.now()
        t.append((end - start).microseconds)


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
    a = random.getrandbits(128)
    start = datetime.now()
    m = primality.millerRabin(a, 10)
    end = datetime.now()
    ms.append((end - start).microseconds)

    start = datetime.now()
    l = primality.lucasTest(a)
    end = datetime.now()
    ls.append((end - start).microseconds)

    avg = sum(ms) / len(ms)
    avg1 = sum(ls) / len(ls)
    print(avg)
    print(avg1)
    print(count)


def testShaweTaylor():

    length = 1024

    t = []
    t1 = []
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
