import secrets
from ptCrypt.Math.smallPrimes import SMALL_PRIMES


def gcd(n: int, m: int) -> int:
    """Euklidean algorithm. Finds greatest common divisor of n and m

    Parameters:
        n: int
            first number
        m: int
            second number

    Returns: 
        result: int
            greatest common divisor of n and m.
    """

    if not n:
        return m
    if not m:
        return n

    while n:
        n, m = m % n, n
    return m


def egcd(n: int, m: int) -> dict:
    """Extended Euklidean algorithm. Finds greatest common divisor of n and m

    Parameters:
        n: int
            first number
        m: int
            second number

    Returns: 
        result: dict
            dictionary with specified keys:
            reminder: int
                greatest common divisor
            a, b: int
                answers to equation an + bm = reminder
    """

    a, a_ = 0, 1
    b, b_ = 1, 0

    c, d = n, m

    q = c // d
    r = c % d
    while r:
        c, d = d, r
        a_, a = a, a_ - q * a
        b_, b = b, b_ - q * b

        q = c // d
        r = c % d

    return (d, a, b)


def isPerfectSquare(p: int) -> bool:
    """Checks if given number is a perfect square. 
    A perfect square is an integer that is a square of another integer.

    Parameters:
        p: int
            number to check
    
    Returns:
        result: bool
            True if number is a perfect square
            False if number is not a perfect square
    """
    
    if p <= 1: return False

    x = p // 2
    seen = set([x])
    while x * x != p:
        x = (x + (p // x)) // 2
        if x in seen: return False
        seen.add(x)
    return True


def jacobiSymbol(a, n):
    """Recursive Jacobi symbol calculation
    Details:
    https://en.wikipedia.org/wiki/Jacobi_symbol

    Algorithm specified in FIPS 186-4, Appendix C.5

    Parameters:
        a: int
            numerator
        
        n: int
            denominator

    Returns:
        result: int
            returns Jacobi symbol (-1; 0; 1) or None, if 
            Jacobi symbol is not defined (for even and negative numbers)
    """

    if n <= 0 or n % 2 == 0: return None

    # Steps 1, 2 and 3
    a = a % n
    if a == 1 or n == 1: return 1
    if a == 0: return 0

    # Step 4
    e = 0
    a1 = a
    while a1 % 2 == 0:
        a1 >>= 1
        e += 1

    # Step 5
    if (e & 1) == 0: s = 1
    elif n % 8 in (1, 7): s = 1
    else: s = -1

    # Step 6
    if n % 4 == 3 and a1 % 4 == 3: s = -s

    # Step 7
    n1 = n % a1

    # Step 8
    return s * jacobiSymbol(n1, a1)



def eulersTotient(n: int, factors: list = None) -> int:
    """Function counts the positive integers up to a given integer n that are
    relatively prime to n. More about Euler's function:
    https://en.wikipedia.org/wiki/Euler%27s_totient_function

    Parameters:
        n: int
            number to be processed
        
        factors: list
            list of prime factors of n. If left empty, n is considered to be prime.
            Note, that function will NOT check for primality or try to factorize n

    Returns: 
        result: int
            Euler's totient of given number
    """

    if factors:
        count = {}
        for f in factors:
            count[f] = factors.count(f)
        result = 1
        for f in factors:
            result *= (f ** (count[f] - 1)) * (f - 1)
    else:
        return n - 1

    return result


def iroot(a, b):
    """Function to calculate a-th integer root from b. Example: iroot(2, 4) == 2

    Parameters:
        a: int
            Root power
        
        b: int
            Number to calculate root from
        
    Returns:
        result: int
            Integer a-th root of b
    """

    if b < 2:
        return b
    a1 = a - 1
    c = 1
    d = (a1 * c + b // (c ** a1)) // a
    e = (a1 * d + b // (d ** a1)) // a
    while c not in (d, e):
        c, d, e = d, e, (a1 * e + b // (e ** a1)) // a
    return min(d, e)


def intToBytes(n: int, length: int = 0, byteorder: str = "big") -> bytes:
    """Converts given integer number to bytes object

    Parameters:
        n: int
            number to convert to bytes
        
        byteorder: str
            order of bytes. Big endian by default
    
    Returns:
        result: bytes
            list of bytes of number n
    """

    nSize = (n.bit_length() + 7) // 8
    if nSize > length: return n.to_bytes(nSize, byteorder.lower())
    else: return n.to_bytes(length, byteorder.lower())


def byteLength(n: int) -> int:
    """Returns minimal amount of bytes to write given number

    Parameters:
        n: int

    Returns:
        result: int
            minimal amount of bytes to write n
    """
    return (n.bit_length() + 7) // 8


def bytesToInt(b: bytes, byteorder: str = "big") -> int:
    """Converts given bytes object to integer number

    Parameters:
        b: bytes
            bytes to convert into number
        
        byteorder: str
            order of bytes. Big endian by default
    
    Returns:
        result: int
            bytes converted to int
    """
    return int.from_bytes(b, byteorder)


def partition(b: bytes, length: int) -> list:
    """Partitions given byte string into list of byte strings of requested length

    Parameters:
        b: bytes
            byte string to partition
        
        length: int
            required part length
    
    Returns:
        result: list
            list of byte strings with required length or less
    """

    partsCount = len(b) // length
    if len(b) % length: partsCount += 1

    result = []
    for i in range(partsCount):
        if i * length + length > len(b): result.append(b[i * length:])
        else: result.append(b[i * length:i * length + length])
    return result


def xor(a: bytes, b: bytes, repeat: bool = False) -> bytes:
    """XORs two byte strings

    Parameters:
        a, b: bytes
            byte strings to XOR
        
    Returns:
        result: bytes
            XOR result
    """

    if repeat: iterations = max(len(a), len(b))
    else: iterations = min(len(a), len(b))

    result = b""
    for i in range(iterations):
        result += bytes([a[i % len(a)] ^ b[i % len(b)]])
    
    return result


def getRandomBytes(count: int, exclude: set = set()) -> bytes:
    """Returns random byte string with required length
    Bytes are generated with secrets module, so returned value should be
    appropriate for cryptographic usage.

    Parameters:
        count: int
            required length

        exclude: set
            set of int values, that must not appear in generated string

    Returns:
        result: bytes
            generated byte string
    """

    result = b""
    while len(result) != count:
        value = secrets.randbits(8)
        if value not in exclude:
            result += intToBytes(secrets.randbits(8))
    return result