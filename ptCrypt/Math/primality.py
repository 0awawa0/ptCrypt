import random
from typing import Iterable
from ptCrypt.Math import base, smallPrimes
from ptCrypt.Asymmetric.ECC import Curve
from datetime import datetime
import hashlib


def millerRabin(p: int, t: int) -> bool:
    """Miller-Rabin primality test. Error probability is (1/4)^t
    More about Miller-Rabin test:
    https://en.wikipedia.org/wiki/Miller–Rabin_primality_test

    To get same error probability with better performance consider 
    using less Miller-Rabin tests followed by one Lucas test.
    For example, FIPS 186-4 (DSA standard) recommends switching from 
    64 Miller-Rabin test to 19 Miller-Rabin tests followed by one Lucas 
    test for 160 bit prime q.

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
    It is recommended to run Lucas test after  few Miller-Rabin tests.
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
    if n % 2 == 0 or base.isPerfectSquare(n): return False

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
        s = base.jacobiSymbol(d, n)
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


def trialDivisionTest(n: int) -> bool:
    """Test for primality by trial division. Unlike Lucas test or Miller-Rabin test, this 
    test is deterministic, but it is extremely slow. You should run this test only for
    small numbers of size around 32-bits.

    Parameters:
        n: int
            Number to check for primality
    
    Returns:
        result: bool
            True if number is definitely prime
            False if number is definitely not prime
    """

    root = base.iroot(2, n)
    if root * root == n: return False

    for prime in smallPrimes.SMALL_PRIMES:
        if n == prime: return True
        if n % prime == 0: return False
        if prime > n: return True
    
    x = smallPrimes.SMALL_PRIMES[-1]
    while x <= root:
        if n % x == 0: return False
        x += 2
    
    return True


def getPrime(n: int, checks: int = 10) -> int:
    """Generates random probable prime number using Miller-Rabin test

    Parameters:
        n: int
            bit length of generated number
            returned number is guaranteed to have this bit length

        checks: int
            count of primality checks to perform

    Returns: 
        result: int
            probable prime number with probability 0.25**(checks)
    """

    while True:
        if n <= 1: return

        num = random.getrandbits(n) | (2 ** (n - 1) + 1)

        def check_small_primes(n):
            for p in smallPrimes.SMALL_PRIMES:
                if n == p: return True
                if n % p == 0: return False
            return True

        if not check_small_primes(num): continue
        if millerRabin(num, checks): return num


def primeFactors(n: int) -> list:
    """Naive integer factorization function. Extremely slow.

    The fucntion first checks if the number is prime with 10 Miller-Rabin tests,
    and if it is then function will return list with only this particular number.

    Then, function divides given number by 2, 3, 5, 7, 9 and so on until it reaches
    square root of given number or until numbers is not equal to 1.

    Parameters:
        n: int
            number to be factorized

    Returns: 
        result: list
            all factors of n
    """
    if millerRabin(n, 10): return [n]

    factors = []
    while n % 2 == 0:
        factors.append(2)
        n = n // 2
    
    sqRoot = base.iroot(2, n)
    for i in range(3, sqRoot, 2):
        while n % i == 0:
            n = n // i
            factors.append(i)
        if n == 1:
            break
    if n > 1:
        factors.append(n)
    return factors


def pollardFactor(n, init=2, bound=2**16, numbers: Iterable = smallPrimes.SMALL_PRIMES):
    """Pollard's p - 1 factorization method. This is a general customizable method.

    More details:
    https://en.wikipedia.org/wiki/Pollard%27s_p_%E2%88%92_1_algorithm

    Parameters:
        n: int
            number to be factorized

        init: int
            initial value, 2 by default

        bound:
            smoothness bound, 65536 by default
        
        numbers: Iterable
            numbers that method must use for powers of init value.
            Note, that method doesn't just raise init to some ith power of the given iterable
            but searches for such power of ith number, that this power is greater or equal to smoothness bound.
            This trick generally increases success rate of the method. 
            If None given, list of small primes from smallPrimes module will be used.
            For list of small primes method successfully find factors up to 38 bits long.
    
    Returns:
        result: int
            prime divisor of n or None if algorithm fails
    """
    a = init

    for i in numbers:
        if i <= 1: continue

        power = i
        while power < bound: power *= i

        a = pow(a, power, n)
        d = base.gcd(a - 1, n)
        if d > 1 and d < n: return d
        if d == n: return None
    return None


def shaweTaylor(length: int, inputSeed: int, hashFunction: callable=hashlib.sha256) -> dict:
    """Shawe-Taylor random prime generation routine. Generated number is definitely prime.
    The algorithm is slow, but will with great chance work faster than getPrime function 
    up to 512 bit numbers.

    Algorithm specified by FIPS 186-4, Appendix C.6

    Parameters:
        length: int
            the length of the prime to be generated
        
        inputSeed: int
            the seed to be used for the generation of the requested prime

        hashFunction: callable
            hash function used during generation. The function must conform to 
            hashlib protocols. By default hashlib.sha256 is used

    Returns:
        dictionary with keys:
            status: bool
                True if generation succeeded
                False if generation failed
            
            prime: int
                generated prime number
            
            primeSeed: int
                a seed determined during generation
            
            primeGenCounter: int
                a counter determined during the generation of the prime
    """

    # Step 1
    if length < 2: return { "status": False, "prime": None, "primeSeed": None, "primeGenCounter": None}

    twoPowLengthMin1 = pow(2, length - 1)

    # Step 2
    if length < 33:

        # Steps 3, 4
        primeSeed = inputSeed
        primeGenCounter = 0

        while True:

            # Hash calculation for step 5
            hashPayload = base.intToBytes(primeSeed)
            hashPayload1 = base.intToBytes(primeSeed + 1)
            h = base.bytesToInt(hashFunction(hashPayload).digest())
            h1 = base.bytesToInt(hashFunction(hashPayload1).digest())

            # Steps 5, 6, 7
            #   c = Hash(primeSeed) ^ Hash(primeSeed + 1)
            c = h ^ h1
            #   c = 2^(length - 1) + (c mod 2^(length - 1))
            c = twoPowLengthMin1 + (c % twoPowLengthMin1)
            #   c = (2 * floor(c / 2)) + 1
            c = (2  * c // 2) + 1

            # Steps 8, 9
            primeGenCounter += 1
            primeSeed += 2

            # Step 10
            if trialDivisionTest(c):
                # Step 11
                return {"status": True, "prime": c, "primeSeed": primeSeed, "primeGenCounter": primeGenCounter}
            
            # Step 12
            if primeGenCounter > 4 * length:
                return {"status": False, "prime": None, "primeSeed": None, "primeGenCounter": None}
    
    # Step 14
    #   smallerLength = ceil(length / 2) + 1
    smallerLength = length // 2 + length % 2 + 1
    recursiveResult = shaweTaylor(smallerLength, inputSeed, hashFunction)

    status = recursiveResult["status"]
    c0 = recursiveResult["prime"]
    primeSeed = recursiveResult["primeSeed"]
    primeGenCounter = recursiveResult["primeGenCounter"]

    # Step 15
    if not status: return {"status": False, "prime": None, "primeSeed": None, "primeGenCounter": None}

    # Steps 16, 17
    outlen = hashFunction().digest_size * 8

    #   iterations = ceil(length / outlen) - 1
    iterations = length // outlen + (length % outlen != 0) - 1

    oldCounter = primeGenCounter

    twoPowOutlen = pow(2, outlen)
    twoPowLengthMin1 = pow(2, length - 1)

    #Step 18
    x = 0

    # Step 19
    for i in range(iterations + 1):
        hashPayload = base.intToBytes(primeSeed + i)
        h = base.bytesToInt(hashFunction(hashPayload).digest())
        x = x + h * pow(twoPowOutlen, i)
    
    # Steps 20, 21, 22
    primeSeed = primeSeed + iterations + 1
    x = twoPowLengthMin1 + (x % twoPowLengthMin1)

    #   t = ceil(x / (2 * c0))
    t = x // (2 * c0) + (x // (2 * c0) != 0)

    while True:
        # Steps 23, 24, 25
        if 2 * c0 + 1 > pow(2, length):
            #   t = ceil(2 ^ (length - 1) / (2 * c0))
            t = twoPowLengthMin1 // (2 * c0) + (twoPowLengthMin1 % (2 * c0) != 0)
    
        c = 2 * t * c0 + 1
        primeGenCounter += 1

        # Step 26
        a = 0

        # Step 27
        for i in range(iterations + 1):
            hashPayload = base.intToBytes(primeSeed + i)
            h = base.bytesToInt(hashFunction(hashPayload).digest())
            a = a + h * pow(twoPowOutlen, i)

        # Steps 28, 29, 30
        primeSeed = primeSeed + iterations + 1
        a = 2 + (a % (c - 3))
        z = pow(a, 2 * t, c)

        # Step 31
        if 1 == base.gcd(z - 1, c) and 1 == pow(z, c0, c):
            return {"status": True, "prime": c, "primeSeed": primeSeed, "primeGenCounter": primeGenCounter}
    
        # Step 32
        if primeGenCounter >= (4 * length + oldCounter):
            return {"status": False, "prime": None, "primeSeed": None, "primeGenCounter": None}

        # Step 33
        t = t + 1


def lenstraFactor(n: int, bound = 2**64, numbers: Iterable = smallPrimes.SMALL_PRIMES[:100], timeout = None) -> int:
    """Lenstra elliptic curve factorization method

    Parameter:
        n: int
            number to be factorized
        
        bound:
            smoothness bound, 65536 by default
        
        numbers: Iterable
            numbers that method must use for multipliers of points.
            Method doesn't just multiply points with some ith number
            but searches for such power of ith number, that this power is 
            greater or equal to smooth bound.
            This trick generlaly increases success rate of the method.
            By default first 100 prime numbers is used.
        
        timeout: int
            factorization timeout in seconds. By default None meaning no timeout.
            Without timeout method never returns until it finds prime divisor of n.
    
    Returns:
        result: int
            prime divisor of n or None if timeout reached
    """

    start = datetime.now()
    curvesCount = 0

    while 1:
        
        curvesCount += 1
        if timeout and (datetime.now() - start).seconds > timeout:
            return None

        a = random.randint(2, n - 1)
        b = random.randint(2, n - 1)
        A = random.randint(2, n - 1)

        B = (pow(b, 2, n) - pow(a, 3, n) - A * a) % n
        g = base.gcd(4 * pow(A, 3) + 27 * pow(B, 2), n)
        if g > 1 and g < n: return g

        curve = Curve.Curve(A, B, n)
        P = curve.point(a, b)
        if curve.hasSingularPoints(): continue

        for number in numbers:
            t = number
            while t < bound: t *= number

            Q = t * P
            if type(Q) is int:
                if Q < n: return Q
                break
            P = Q


