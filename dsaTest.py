from Asymmetric import DSA
from datetime import datetime
import hashlib


def testProbablePrimeGeneration():

    from Crypto.PublicKey import DSA

    start = datetime.now()
    print(DSA.generate(1024))
    end = datetime.now()
    print((end - start).seconds)

    # t = []

    # for i in range(10):
    #     start = datetime.now()
    #     N, L = DSA.APPROVED_LENGTHS[1]
    #     params = DSA.generateProbablePrimes(N, L, N, hashlib.sha256)
    #     print(params.beautyRepr(1))
    #     end = datetime.now()
    #     t.append((end - start).seconds)
    
    # avg = sum(t) / len(t)
    # print(f"Avg time: {avg} seconds")


if __name__ == "__main__":
    testProbablePrimeGeneration()
