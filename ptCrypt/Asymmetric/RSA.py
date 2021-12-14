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
    return randbits(2 * secLvl)
