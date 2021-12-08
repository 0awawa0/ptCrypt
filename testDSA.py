from Asymmetric import DSA
from datetime import datetime
import hashlib
from Math import primality


def testProbablePrimeGeneration():
    t = []
    for _ in range(10):
        start = datetime.now()
        N, L = DSA.APPROVED_LENGTHS[1]
        params = DSA.generateProbablePrimes(N, L, N, hashlib.sha256)
        end = datetime.now()
        t.append((end - start).seconds)

        p = params.primes.p
        q = params.primes.q
        assert primality.millerRabin(p, 10)
        assert primality.millerRabin(q, 10)
        assert (p - 1) % q == 0
    
    avg = sum(t) / len(t)
    print(f"Avg time: {avg} seconds")

def testProbablePrimeVerification():
    for i in range(25):
        N, L = DSA.APPROVED_LENGTHS[0]
        params = DSA.generateProbablePrimes(N, L, N)
        assert DSA.verifyProbablePrimesGenerationResult(params)

def testProvablePrimeGeneration():
    t = []
    for _ in range(10):
        start = datetime.now()
        N, L = DSA.APPROVED_LENGTHS[0]
        firstSeed = DSA.getFirstSeed(N, N)
        params = DSA.generateProvablePrimes(N, L, firstSeed)
        end = datetime.now()
        t.append((end - start).seconds)
    
    avg = sum(t) / len(t)
    print(f"Avg time: {avg} seconds")


def testProvablePrimeVerification():
    for _ in range(25):
        N, L = DSA.APPROVED_LENGTHS[0]
        firstSeed = DSA.getFirstSeed(N, N)
        params = DSA.generateProvablePrimes(N, L, firstSeed)
        assert DSA.verifyProvablePrimesGenerationResult(params)

if __name__ == "__main__":
    # testProbablePrimeGeneration()
    # testProvablePrimeGeneration()
    # testProbablePrimeVerification()
    testProvablePrimeVerification()
