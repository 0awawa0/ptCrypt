from Asymmetric import DSA
from datetime import datetime
import hashlib


def testProbablePrimeGeneration():
    t = []
    for _ in range(100):
        start = datetime.now()
        N, L = DSA.APPROVED_LENGTHS[0]
        params = DSA.generateProbablePrimes(N, L, N, hashlib.sha256)
        print(params.beautyRepr(1))
        end = datetime.now()
        t.append((end - start).seconds)
    
    avg = sum(t) / len(t)
    print(f"Avg time: {avg} seconds")


if __name__ == "__main__":
    testProbablePrimeGeneration()
