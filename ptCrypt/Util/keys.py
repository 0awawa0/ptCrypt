import hashlib


FFC_APPROVED_LENGTHS = [
    (160, 1024),
    (224, 2048),
    (256, 2048),
    (256, 3072),
    (384, 7680),
    (512, 15360)
]

IFC_APPROVED_LENGTHS = [
    1024,
    2048,
    3072,
    7680,
    15360
]


ECC_APPROVED_LENGTHS = [
    160,
    224,
    256,
    384,
    512
]


APPROVED_HASHES = [
    hashlib.sha1,
    hashlib.sha224,
    hashlib.sha256,
    hashlib.sha384,
    hashlib.sha512
]


def getFFCSecurityLevel(N: int, L: int) -> int:
    """Returns security level of lengths pair for finite-field cryptography (DSA, DH, MQV)
    according to NIST SP800-57

    Given pair must be in FFC_APPROVED_LENGTHS, otherwise 0 is returned.

    Parameters:
        N: int
            smaller number bit length
        
        L: int
            bigger number bit length
    
    Returns:
        result: int
            Associated security level
    """

    if (N, L) not in FFC_APPROVED_LENGTHS: return 0
    elif (N, L) == FFC_APPROVED_LENGTHS[0]: return 80
    elif (N, L) == FFC_APPROVED_LENGTHS[1]: return 112
    elif (N, L) == FFC_APPROVED_LENGTHS[2]: return 128
    elif (N, L) == FFC_APPROVED_LENGTHS[3]: return 192
    elif (N, L) == FFC_APPROVED_LENGTHS[4]: return 256
    else: return 0


def getIFCSecurityLevel(N: int) -> int:
    """Returns security level of bit length for integer-factorization cryptography (RSA)
    according to NIST SP800-57

    Given number must be in IFC_APPROVED_LENGTHS, otherwise 0 is returned.

    Parameters:
        N: int
            key bit length
    

    Returns:
        result: int
            Associated security level
    """

    if N not in IFC_APPROVED_LENGTHS: return 0
    elif N == IFC_APPROVED_LENGTHS[0]: return 80
    elif N == IFC_APPROVED_LENGTHS[1]: return 112
    elif N == IFC_APPROVED_LENGTHS[2]: return 128
    elif N == IFC_APPROVED_LENGTHS[3]: return 192
    elif N == IFC_APPROVED_LENGTHS[4]: return 256


def getECCSecurityLevel(N: int):
    """Returns security level of bit length for elliptic-curve cryptography (ECDSA, EDH, EMQV)
    according to NIST SP800-57

    Parameters:
        N: int
            key bit length
    
    Returns:
        result: int
            Associated security level
    """

    if N < ECC_APPROVED_LENGTHS[0]: return 0
    elif N in range(ECC_APPROVED_LENGTHS[0], ECC_APPROVED_LENGTHS[1]): return 80
    elif N in range(ECC_APPROVED_LENGTHS[1], ECC_APPROVED_LENGTHS[2]): return 112
    elif N in range(ECC_APPROVED_LENGTHS[2], ECC_APPROVED_LENGTHS[3]): return 128
    elif N in range(ECC_APPROVED_LENGTHS[3], ECC_APPROVED_LENGTHS[4]): return 192
    else: return 256


def getFFCKeyLength(securityLevel: int) -> tuple:
    """Returns appropriate pair of bit lengths for keys to get required security level
    for finite-field cryptography according to NIST SP800-57

    Parameters:
        securityLevel: int
            required security level
    
    Returns:
        result: tuple
            Pair of appropriate bit lengths for keys as tuple (smallerLength, biggerLength)
            Note that if you need to conform to NIST standards you should use exact values returned from thsi function
    """

    if securityLevel <= 80: return FFC_APPROVED_LENGTHS[0]
    elif securityLevel in range(81, 113): return FFC_APPROVED_LENGTHS[1]
    elif securityLevel in range(113, 129): return FFC_APPROVED_LENGTHS[2]
    elif securityLevel in range(129, 193): return FFC_APPROVED_LENGTHS[3]
    else: return FFC_APPROVED_LENGTHS[4]


def getIFCKeyLength(securityLevel: int) -> int:
    """Retuns minimal key length to get requried security level for integer-factorization cryptography
    according to NIST SP800-57

    Parameters:
        securityLevel: int
            required security level
    
    Returns:
        result: int
            Bit length of key to use to get required security level. 
            Note that if you need to conform to NIST standards 
            you should use exact value returned from this function
    """

    if securityLevel <= 80: return IFC_APPROVED_LENGTHS[0]
    elif securityLevel in range(81, 113): return IFC_APPROVED_LENGTHS[1]
    elif securityLevel in range(113, 129): return IFC_APPROVED_LENGTHS[2]
    elif securityLevel in range(129, 193): return IFC_APPROVED_LENGTHS[3]
    else: return IFC_APPROVED_LENGTHS[4]


def getECCKeyLength(securityLevel: int) -> int:
    """Returns minimal key length to get required security level for elliptic-curve cryptography
    according to NIST SP800-57

    Parameters:
        securityLevel: int

    Returns:
        result: int
            Bit length of key to use to get required security level.
    """

    if securityLevel <= 80: return ECC_APPROVED_LENGTHS[0]
    elif securityLevel in range(81, 113): return ECC_APPROVED_LENGTHS[1]
    elif securityLevel in range(113, 129): return ECC_APPROVED_LENGTHS[2]
    elif securityLevel in range(129, 193): return ECC_APPROVED_LENGTHS[3]
    else: return ECC_APPROVED_LENGTHS[4]