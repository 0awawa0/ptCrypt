from Asymmetric.DSA import DSA

for i in range(10):
    for lengths in DSA.APPROVED_LENGTHS:
        N, L = lengths
        params = DSA.generateProbablePrimes(N, L, L)
        print(params.beautyRepr(1))
        assert DSA.verifyProbablePrimesGenerationResult(params)
        print("Parameters verified")
