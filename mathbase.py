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

    return {"reminder": d, "a": a, "b": b}


def millerRabin(p: int, t: int) -> bool:
    """Miller-Rabin primality test. Error probability is (1/4)^t
    More about Miller-Rabin test:
    https://en.wikipedia.org/wiki/Miller–Rabin_primality_test

    Parameters:
        p: int
            number to be tested
        t: int
            count of tests

    Returns: 
        result: bool
            True if the number is prime, else - False
    """
    if p <= 1:
        return False

    k = 1
    b = 0
    while (p - 1) % k == 0:
        b += 1
        k = k << 1

    k = k >> 1
    b -= 1
    m = (p - 1) // k

    for _ in range(t):
        a = random.getrandbits(p.bit_length())
        z = pow(a, m, p)

        if z == 1 or z == p - 1: continue

        for _ in range(b - 1):
            z = pow(z, 2, p)
            if z == 1: return False
            if z == p - 1: break

        if z == p - 1: continue
        return False

    return True


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

        # Here I use random.getrandbits to generate n random bits
        # Although higher bits might be 0, so actually this number may have
        # bit length less then n.
        # Moreover, lowest bit might be 0, so this number is not prime
        # To fix this I switch lowest bit to 1, and after that, while
        # the bit length of number less than n I complete it with 1 and 0.
        # For example, n = 4, but generated 0010, so it's 2. And actual bit
        # length is 2 (10). So I do this:
        # 1) Switch lowest bit to 1 and I get number 3 -> 11
        # 2) Complete number to 4 bits, so that highest bit is 1: 11 -> 1011
        if n <= 1:
            return

        num = random.getrandbits(n) | (2 ** (n - 1) + 1)

        # Now I has actual n bits number, but I cant say that it's prime
        # So I check it
        # First, I check if the number is divisible by any of prime numbers
        # from 2 to 200
        def check_small_primes(n):
            for p in SMALL_PRIMES:
                if n % p == 0 and n != p:
                    return False
            return True

        if not check_small_primes(num):
            continue

        # If it's not, I run Miller-Rabin test 10 times for this number
        # If number passes the test I return it. And it's prime with the
        # probability of 0.9999990463256836
        if millerRabin(num, checks):
            return num


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
        if d > 1 and d < n:
            return d
        if d == n:
            return None
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
