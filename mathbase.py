import random
from smallPrimes import SMALL_PRIMES


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


def millerRabin(p: int, t: int) -> bool:
    """Miller-Rabin primality test. Error probability is (1/4)^t
    More about Miller-Rabin test:
    https://en.wikipedia.org/wiki/Miller–Rabin_primality_test

    Algorithm also specified in FIPS 186-4, Appendix C.3.1

    Parameters:
        p: int
            number to be tested
        t: int
            count of tests

    Returns: 
        result: bool
            True if the number is prime, else - False
    """
    if p <= 1: return False

    # Step 1. Find largest a such that (p - 1) % 2^a == 0
    k = 1
    b = 0
    while (p - 1) % k == 0:
        b += 1
        k = k << 1
    k = k >> 1
    b -= 1

    # Step 2. m = (p - 1) / 2^a
    m = (p - 1) // k

    # Step 3. wlen = len(w)
    plen = p.bit_length()

    # Step 4
    for _ in range(t):

        # Steps 4.1 and 4.2
        a = random.getrandbits(plen)
        if a <= 1 or a >= p - 1: continue

        # Step 4.3 and 4.4
        z = pow(a, m, p)
        if z == 1 or z == p - 1: continue

        # Step 4.5
        for _ in range(b - 1):
            # Steps 4.5.1, 4.5.2 and 4.5.3
            z = pow(z, 2, p)
            if z == 1: return False
            if z == p - 1: break

        if z == p - 1: continue

        # Step 4.6
        return False

    # Step 5
    return True


def lucasTest(n: int) -> bool:
    """Lucas pseudoprime primality test. Error probability 4/15
    Algorithm specified in FIPS 186-4, Appendix C.3.3

    Parameters:
        n: int
            number to be tested
    
    Returns:
        result: bool
            True if number is probably prime
            False if number is definitely composite
    """

    # Step 1
    if n % 2 == 0 or isPerfectSquare(n): return False

    # Step 2
    def sequence():
        value = 5
        while True:
            yield value
            if value > 0:
                value += 2
            else:
                value -= 2
            value = -value
    
    for d in sequence():
        s = jacobiSymbol(d, n)
        if s == 0: return False
        if s == -1: break

    # Step 3
    K = n + 1

    r = K.bit_length() - 1

    # Step 5
    Ui = 1
    Vi = 1

    Ut = 0
    Vt = 0

    invOfTwo = pow(2, -1, n)

    # Step 6
    for i in range(r - 1, -1, -1):
        # Step 6.1
        Ut = (Ui * Vi) % n

        # Step 6.2
        Vt = (Ui * Ui * d + Vi * Vi) % n
        Vt = (Vt * invOfTwo) % n

        # Step 6.3
        if (K >> i) & 1:
            # Steps 6.3.1 and 6.3.2
            Ui = ((Ut + Vt) * invOfTwo) % n
            Vi = ((Vt + Ut * d) * invOfTwo) % n
        else:
            # Steps 6.3.3 and 6.3.4
            Ui = Ut
            Vi = Vt
    
    # Step 7
    return Ui == 0



def getPrime(n: int, checks: int = 10) -> int:
    """Function generates random prime number with bit length equals n

    Parameters:
        n: int
            bit length of generated number

        checks: int
            count of primality checks to perform

    Returns: 
        result: int
            number probable with probability 0.25**(checks)
    """
    while True:
        if n <= 1: return

        num = random.getrandbits(n) | (2 ** (n - 1) + 1)

        def check_small_primes(n):
            for p in SMALL_PRIMES:
                if n == p: return True
                if n % p == 0: return False
            return True

        if not check_small_primes(num): continue
        if millerRabin(num, checks): return num


def isPerfectSquare(p: int) -> bool:
    """Checks if given number is a perfect square

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


def primeFactors(n: int) -> list:
    """Naive integer factorization function

    Parameters:
        n: int
            number to be factorized

    Returns: 
        result: list
            all factors of n
    """
    if millerRabin(n, 10):
        return [n]

    import math
    factors = []
    while n % 2 == 0:
        factors.append(2)
        n = n // 2
    sq_root = round(math.sqrt(n))
    for i in range(3, sq_root, 2):
        while n % i == 0:
            n = n // i
            factors.append(i)
        if n == 1:
            break
    if n > 1:
        factors.append(n)
    return factors


def pollardFactor(n, init=2, bound=2**16):
    """Pollard's p - 1 factorization method
    More details:
    https://en.wikipedia.org/wiki/Pollard%27s_p_%E2%88%92_1_algorithm

    Parameters:
        n: int
            number to be factorized
        init: int
            initial value
        bound:
            smoothness bound
    
    Returns:
        result: int
            prime divisor of n or None if algorithm fails
    """
    a = init
    for prime in SMALL_PRIMES:

        power = 1
        while power < bound:
            a = pow(a, prime, n)
            power *= prime

        d = gcd(a - 1, n)
        if d > 1 and d < n: return d
        if d == n: return None
    return None


def eulersTotient(n: int, factors: list = None) -> int:
    """Function counts the positive integers up to a given integer n that are
    relatively prime to n. More about Euler's function:
    https://en.wikipedia.org/wiki/Euler%27s_totient_function

    Parameters:
        n: int
            number to be processed

    Returns: 
        result: int
            Euler's totient of given number
    """
    if millerRabin(n, 10):
        return n - 1

    if factors:
        mul = 1
        for f in factors:
            mul *= f

        if mul != n:
            n_factors = set(primeFactors(n))
        else:
            n_factors = set(factors)
    else:
        factors = primeFactors(n)
        n_factors = set(factors)

    count = {}
    for f in n_factors:
        count[f] = factors.count(f)
    result = 1
    for i in n_factors:
        result *= (i ** (count[i] - 1)) * (i - 1)

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


def intToBytes(n: int, byteorder: str = "big") -> bytes:
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

    return n.to_bytes((n.bit_length() + 7) // 8, byteorder.lower())


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
