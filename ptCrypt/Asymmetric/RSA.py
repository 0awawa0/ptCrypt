import random
import secrets
from ptCrypt.Math import base, primality
from ptCrypt.Util.keys import IFC_APPROVED_LENGTHS, getIFCSecurityLevel, millerRabinTestsForIFC, getIFCAuxiliaryPrimesLegths
from secrets import randbits


def getSeed(N: int) -> int:
    """Returns seed appropriate for provable primes generation
    according to algorithm from NIST FIPS 186-4, Appendix B.3.2.1.
    This function uses OS random generator, which is supposed to 
    be secure enough for cryptographic usage.

    Parameters:
        N: int
            key bit length
    
    Returns:
        seed: int
            seed to use for provable primes generation
    """

    if N not in IFC_APPROVED_LENGTHS: return None
    secLvl = getIFCSecurityLevel(N)
    return randbits(2 * secLvl) | 2 ** (2 * secLvl- 1)


def generateProvablePrimes(e: int, N: int, seed: int) -> tuple:
    """Generates provably prime numbers p and q for RSA.
    The algorithm is specified by FIPS 186-4, Appendix B.3.2.2.

    Parameters:
        e: int
            RSA public exponent
        
        N: int
            required key size, which is the modulus size for IFC.
        
        seed: int
            random seed to use for primes generation, 
            use getSeed function to get this value
    
    Returns:
        result: tuple
            generated primes p and q, or None. 
            None might be returned if either passed parameters are not appropriate by FIPS 186-4,
            or the generation simply fails. If parameters are fine, generate new seed with getSeed and
            run the function again.
    """

    # Steps 1, 2, 3 and 4
    if N != 2048 and N != 3072: return None
    if e <= 2**16 or e >= 2**256 or e % 2 == 0: return None
    securityStrength = getIFCSecurityLevel(N)
    if seed.bit_length() != 2 * securityStrength: return None

    # Step 5
    workingSeed = seed

    # Step 6
    L = N // 2
    N1 = 1
    N2 = 1
    firstSeed = workingSeed
    result = primality.ifcProvablePrime(L, N1, N2, firstSeed, e)
    if not result: return None
    p, p1, p2, pSeed = result
    workingSeed = pSeed

    # Step 7
    while True:

        # Step 7.1
        result = primality.ifcProvablePrime(L, N1, N2, workingSeed, e)
        if not result: return None
        q, q1, q2, qSeed = result

        # Step 7.2
        workingSeed = qSeed

        # Step 8
        if abs(p - q) > pow(2, N // 2 - 100): break

    # Steps 9, 10
    pSeed = 0
    qSeed = 0
    workingSeed = 0
    return (p, q)


def generateProbablePrimes(e: int, N: int) -> tuple:
    """Generates probably prime numbers p and q for RSA.
    The algorithm is specified by FIPS 186-4, Appendix B.3.3.

    Parameters:
        e: int
            RSA public exponent
        
        N: int
            required key size, which is the modulus size for IFC.
    
    Returns:
        result: tuple
            generated primes p and q, or None. 
            None might be returned if either passed parameters are not appropriate by FIPS 186-4,
            or the generation simply fails. If parameters are fine, generate new seed with getSeed and
            run the function again.
    """

    # Steps 1, 2
    if N != 2048 and N != 3072: return None
    if e<= 2**16 or e >= 2**256 or e % 2 == 0: return None

    testsCount = millerRabinTestsForIFC(N)[0]
    
    # 665857/470832 = 1.41421356237 is a good rational approximation of sqrt(2)
    coeff1 = 665857 * pow(2, N // 2 - 1) // 470832

    # Step 4
    i = 0
    while True:
        # Steps 4.2 and 4.3
        p = secrets.randbits(N // 2) | 1

        # Step 4.4
        if p < coeff1: continue

        # Step 4.5
        if base.gcd(p - 1, e) == 1:
            if primality.millerRabin(p, testsCount): break
        
        # Steps 4.6, 4.7
        i += 1
        if i >= 5 * N // 2: return None
    
    # Step 5
    i = 0
    while True:
        # Steps 5.2 and 5.3
        q = secrets.randbits(N // 2) | 1

        # Step 5.4
        if abs(p - q) <= pow(2, N // 2 - 100): continue

        # Step 5.5
        if q < coeff1: continue

        # Step 5.6
        if base.gcd(q - 1, e) == 1:
            if primality.millerRabin(q, testsCount): break
        
        # Steps 5.7 and 5.8
        i += 1
        if i >= 5 * N // 2: return None
    
    return (p, q)


def geneareteProvablePrimesWithConditions(e: int, N: int, seed: int) -> tuple:
    """Provable primes generation method which satisfies security conditions from FIPS 186-4.
    Generation algorithm is specified by FIPS 186-4, Appendix B.3.4.

    Parameters:
        e: int
            public exponent for RSA
        
        N: int
            RSA key length
        
        seed: int
            random seed to use for generation
    
    Returns:
        result: tuple
            pair of provably prime numbers p and q such that n = p * q has length N.
            May return None if either passed parameters are incorrect, or generation fails.
            If parameters are good, retry generation with different seed.
    """

    # Steps 1, 2
    if N != 1024 and N != 2048 and N != 3072: return None
    if e <= 2 ** 16 or e >= 2 ** 256: return None

    # Steps 3, 4
    securityLevel = getIFCSecurityLevel(N)
    if seed.bit_length() != 2 * securityLevel: return None

    # Step 5
    workingSeed = seed

    p1Len, p2Len = getIFCAuxiliaryPrimesLegths(N)
    q1Len, q2Len = getIFCAuxiliaryPrimesLegths(N)

    # Step 6
    res = primality.ifcProvablePrime(N // 2, e, workingSeed, p1Len, p2Len)
    if not res: return None

    p, p1, p2, pSeed = res
    workingSeed = pSeed

    # Step 7
    while True:
        res = primality.ifcProvablePrime(N // 2, e, workingSeed, q1Len, q2Len)
        if not res: return None

        q, q1, q2, qSeed = res
        workingSeed = qSeed

        # Step 8
        if abs(p - q) > pow(2, N // 2 - 100): break

    # Steps 9, 10
    qSeed = 0
    pSeed = 0
    workingSeed = 0
    return (p, q)


def generateProbablePrimesWithConditions(e: int, N: int, seed: int, probablePrimes: bool = False) -> tuple:
    """Generates probable primes p and q for RSA by algorithms specified in FIPS 186-4, Appendix B.3.5 and B.3.6.
    This function combines two algorithms, set probablePrimes to False to use algorirthm from Appendix B.3.5. and
    to True to use algorithm from Appendix B.3.6.

    Parameters:
        e: int
            RSA public exponent
        
        N: int
            key length
        
        seed: int
            seed to use for generation, only used for algorithm Appendix B.3.5, so if probablePrimes set to True,
            this value has no effect and can be set to None.
        
        probablePrimes: bool
            specifies which algorithm to use:
                True -> Appendix B.3.6.
                False -> Appendix B.3.5.
    
    Returns:
        result: tuple
            pair of primes p and q or None. None might be returned either if passed parameters are incorrect, or
            if generation fails when probablePrimes is set to False. If parameters are fine, try using different seed.
    """

    # Steps 1, 2
    if N != 1024 and N != 2048 and N != 3072: return None
    if e <= 2 ** 16 or e >= 2 ** 256: return None

    testsCount = millerRabinTestsForIFC(N)[0]

    # Steps 3, 4
    securityLevel = getIFCSecurityLevel(N)
    if not probablePrimes and seed.bit_length() != 2 * securityLevel: return None

    p1Len, p2Len = getIFCAuxiliaryPrimesLegths(N, probablePrimes = probablePrimes)
    q1Len, q2Len = getIFCAuxiliaryPrimesLegths(N, probablePrimes = probablePrimes)

    if not probablePrimes:
        # Step 5.1
        res = primality.shaweTaylor(p1Len, seed)
        if not res["status"]: return None
        p1 = res["prime"]
        primeSeed = res["primeSeed"]

        # Step 5.2
        res = primality.shaweTaylor(p2Len, primeSeed)
        if not res["status"]: return None
        p2 = res["prime"]
        primeSeed = res["primeSeed"]

        # Step 5.3
        p = generateProbablePrimeWithAuxiliaryPrimes(p1, p2, N, e)
        if not p: return None
        p, Xp = p

        while True:
            # Step 6.1
            res = primality.shaweTaylor(q1Len, primeSeed)
            if not res["status"]: return None
            q1 = res["prime"]
            primeSeed = res["primeSeed"]

            # Step 6.2
            res = primality.shaweTaylor(q2Len, primeSeed)
            if not res["status"]: return None
            q2 = res["prime"]
            primeSeed = res["primeSeed"]

            # Step 6.3
            q = generateProbablePrimeWithAuxiliaryPrimes(q1, q2, N, e)
            if not q: return None
            q, Xq = q

            # Step 7
            if abs(p - q) > pow(2, N // 2 - 100) and abs(Xp - Xq) > pow(2, N // 2 - 100): break

    else:
        # Step (4.1)
        Xp1 = secrets.randbits(p1Len) | 2 ** (p1Len - 1) | 1
        Xp2 = secrets.randbits(p2Len) | 2 ** (p2Len - 1) | 1

        # Step (4.2)
        while not primality.millerRabin(Xp1, testsCount): Xp1 += 2
        while not primality.millerRabin(Xp2, testsCount): Xp2 += 2

        # Step (4.3)
        res = generateProbablePrimeWithAuxiliaryPrimes(Xp1, Xp2, N, e)
        if not res: return None

        p, Xp = res

        while True:

            # Step (5.1)
            Xq1 = secrets.randbits(q1Len) | 2 ** (q1Len - 1) | 1
            Xq2 = secrets.randbits(q2Len) | 2 ** (q2Len - 1) | 1

            # Step (5.2)
            while not primality.millerRabin(Xq1, testsCount): Xq1 += 2
            while not primality.millerRabin(Xq2, testsCount): Xq2 += 2

            # Step (5.3)
            res = generateProbablePrimeWithAuxiliaryPrimes(Xq1, Xq2, N, e)
            if not res: return None

            q, Xq = res

            # Step (6)
            if abs(p - q) > 2 ** (N // 2 - 100) and abs(Xp - Xq) > 2 ** (N // 2 - 100): break
    
    # Step 8(7)
    Xp = 0
    Xq = 0
    Xp1 = 0
    Xp2 = 0
    Xq1 = 0
    Xq2 = 0
    primeSeed = 0
    p1 = 0
    p2 = 0
    q1 = 0
    q2 = 0

    return (p, q)


def generateProbablePrimeWithAuxiliaryPrimes(p1: int, p2: int, N: int, e: int) -> tuple:
    """Generates probable prime for RSA with auxilary primes by 
    algorithm specified in FIPS 186-4, Appendix C.9.

    Parameters:
        p1: int
        p2: int
            Auxiliary primes
        
        N: int
            key length
        
        e: int
            RSA public exponent
    
    Returns:
        result: tuple
            Pair of integers: probable prime number 
            and random integer used to generate that number
    """

    testsCount = millerRabinTestsForIFC(N)[0]

    # Steps 1, 2
    if base.gcd(2 * p1, p2) != 1: return None

    # R = 1 mod 2p1 and R = -1 mod p2
    R = (pow(p2, -1, 2 * p1) * p2) - ((pow(2 * p1, -1, p2) * 2 * p1 ))

    assert (R % (2*p1)) == 1 and (R % p2) == (-1 % p2)

    xLowBorder = 665857 // 470832 * pow(2, N // 2 - 1)
    xHighBorder = pow(2, N // 2) - 1

    # Step 3
    while True:
        X = secrets.randbits(N // 2) | 2 ** (N // 2 - 1)
        while X < xLowBorder or X > xHighBorder:
            X = secrets.randbits(N // 2) | 2 ** (N // 2 - 1)

        assert X <= xHighBorder and X >= xLowBorder

        # Step 4
        Y = X + ((R - X) % (2 * p1 * p2))

        # Step 5
        i = 0
        while True:

            # Step 6
            if Y >= pow(2, N // 2): break

            # Step 7
            if base.gcd(Y - 1, e) == 1:
                if primality.millerRabin(Y, testsCount): return (Y, X)

            # Steps 8, 9, 10
            i += 1
            if i >= 5 * (N // 2): return None
            Y = Y + (2 * p1 * p2)
