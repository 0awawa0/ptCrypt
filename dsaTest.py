from Asymmetric import DSA


def testProbablePrimeGeneration():
    N, L = DSA.APPROVED_LENGTHS[-1]
    params = DSA.generateProbablePrimes(N, L, L)
    print(params.beautyRepr(1))
    assert DSA.verifyProbablePrimesGenerationResult(params)
    print("Parameters verified")


if __name__ == "__main__":
    testProbablePrimeGeneration()
