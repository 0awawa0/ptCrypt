from ptCrypt.Math import primality
from ptCrypt.Util.keys import IFC_APPROVED_LENGTHS, getIFCSecurityLevel
from secrets import randbits


def getSeed(N: int) -> int:
    """Returns seed appropriate for provable primes generation
    according to algorithm from NIST FIPS 186-4, Appendix B.3.2.1

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

    if N != 2048 and N != 3072: return None
    if e <= 2**16 or e >= 2**256 or e % 2 == 0: return None

    securityStrength = getIFCSecurityLevel(N)
    if seed.bit_length() != 2 * securityStrength: return None

    workingSeed = seed

    L = N // 2
    N1 = 1
    N2 = 1
    firstSeed = workingSeed

    result = primality.ifcProvablePrime(L, N1, N2, firstSeed, e)
    if not result: return None

    p, p1, p2, pSeed = result

    workingSeed = pSeed

    result = primality.ifcProvablePrime(L, N1, N2, workingSeed, e)
    if not result: return None

    while True:
        q, q1, q2, qSeed = result
        workingSeed = qSeed
        if abs(p - q) > pow(2, N // 2 - 100): break

    pSeed = 0
    qSeed = 0
    workingSeed = 0
    return (p, q)
