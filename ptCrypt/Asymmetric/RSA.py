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

    if N != 1024 and N != 2048 and N != 3072: return None
    if e <= 2 ** 16 or e >= 2 ** 256: return None

    securityLevel = getIFCSecurityLevel(N)
    if seed.bit_length() != 2 * securityLevel: return None

    workingSeed = seed

    p1Len, p2Len = getIFCAuxiliaryPrimesLegths(N)
    q1Len, q2Len = getIFCAuxiliaryPrimesLegths(N)

    res = primality.ifcProvablePrime(N // 2, e, workingSeed, p1Len, p2Len)
    if not res: return None

    p, p1, p2, pSeed = res
    
    workingSeed = pSeed

    while True:
        res = primality.ifcProvablePrime(N // 2, e, workingSeed, q1Len, q2Len)
        if not res: return None

        q, q1, q2, qSeed = res
        workingSeed = qSeed
        if abs(p - q) > pow(2, N // 2 - 100): break
    
    qSeed = 0
    pSeed = 0
    workingSeed = 0
    return (p, q)


def generateProbablePrimesWithConditions(e: int, N: int, seed: int, provablePrimes: bool = True) -> tuple:

    if N != 1024 and N != 2048 and N != 3072: return None
    if e <= 2 ** 16 or e >= 2 ** 256: return None

    securityLevel = getIFCSecurityLevel(N)
    if securityLevel.bit_length() != 2 * securityLevel: return None

    p1Len, p2Len = getIFCAuxiliaryPrimesLegths(N, True)

    res = primality.shaweTaylor(p1Len, seed)
    if not res["status"]: return None

    p1 = res["prime"]
    primeSeed = res["primeSeed"]

    res = primality.shaweTaylor(p2Len, primeSeed)
    if not res["status"]: return None

    p2 = res["prime"]
    primeSeed = res["primeSeed"]

