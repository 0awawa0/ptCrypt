from Math import base, primality
import random
import hashlib
from datetime import date, datetime


APPROVED_LENGTHS = [
    (160, 1024),
    (224, 2048),
    (256, 2048),
    (256, 3072)
]


APPROVED_HASHES = [
    hashlib.sha1,
    hashlib.sha224,
    hashlib.sha256,
    hashlib.sha384,
    hashlib.sha512
]


class Primes:
    """Class that encapsulates primes p and q

    Attributes:
        p: int
            Bigger prime
        q: int
            Smaller prime
    """

    def __init__(self, p: int, q: int):
        """Initializes class object with p and q

        Parameters:
            p: int
                Bigger prime
                
            q: int
                Smaller prime
        """

        self.p = p
        self.q = q

    def beautyRepr(self, level: int) -> str:
        """Returns object's beautified string representation

        Parameters:
            level: int
                Indentation level
        """

        indent = "\t" * level
        return f"Primes: \n{indent}p: {hex(self.p)}\n{indent}q: {hex(self.q)}"


class Params:
    """Class that encapsulates basic DSA parameters

    Attributes:
        primes: Primes
            Prime numbers p and q
        g: int
            Gorup generator
    """

    def __init__(self, primes: Primes, g: int):
        """Initializes parameters object with given primes and generator

        Parameters:
            primes: int
                Primes p and q
                
            g: int
                Group generator
        """

        self.primes = primes
        self.g = g

    def beautyRepr(self, level: int) -> str:
        """Returns object's beautified string representation

        Parameters:
            level: int
                Indentation level
        """
        primesRepr = self.primes.beautyRepr(level + 1)
        indent = "\t" * level
        return f"DSA Params: \n{indent}{primesRepr}\n{indent}g: {self.g}"


class ProbablePrimesGenerationResult:
    """Encapsulates result of the probable primes generation
    This result includes status of generation, generated primes and parameters 
    counter and domainParameterSeed used to verify generated primes. 
    See FIPS 186-4 for details

    Attributes:
        status: bool
            True if generation was successful
            False if generation failed
                
        primes: Primes
            primes p and q. If status is False, this field is None
                
        verifyParams: ProbablePrimesGenerationResult.VerifyParams
            domainParameterSeed and counter parameters for primes verification
    """

    class VerifyParams:
        """Encapsulates parameters for primes verification
        See FIPS 186-4 for details

        Attributes:
            domainParameterSeed: int
            counter: int
        """

        def __init__(self, domainParameterSeed: int, counter: int):
            """Initializes object with domainParameterSeed and counter

            Parameters:
                domainParameterSeed: int
                    domain_parameter_seed value for primes verification
                        
                counter: int
                    counter value for primes verification
                    
            See FIPS 186-4 for details
            """

            self.domainParameterSeed = domainParameterSeed
            self.counter = counter

        def beautyRepr(self, level: int) -> str:
            """Returns object's beautified string representation

            Parameters:
                level: int
                    Indentation level
            """
            indent = "\t" * level
            return f"ProbablePrimesVerifyParams:\n{indent}domainPrameterSeed: {hex(self.domainParameterSeed)}\n{indent}counter: {hex(self.counter)}"

    def __init__(self, status: bool, primes: Primes, verifyParams: VerifyParams):
        """Initializes object with status, primes and verification parameters

        Parameters:
            status: bool
                Generation status, indicates if generation was successful
                    
            primes: Primes
                Generated prime numbers
                    
            verifyParams: ProbablePrimesGenerationResult.VerifyParams
                Parameters for primes verification
        """

        self.status = status
        self.primes = primes
        self.verifyParams = verifyParams

    def beautyRepr(self, level: int) -> str:
        """Returns object's beautified string representation

        Parameters:
            level: int
                Indentation level
        """

        primesRepr = self.primes.beautyRepr(level + 1)
        verifyParamsRepr = self.verifyParams.beautyRepr(level + 1)
        indent = "\t" * level
        return f"ProbablePrimesGenerationResult: \n{indent}status: {self.status}\n{indent}{primesRepr}\n{indent}{verifyParamsRepr}"


class ProvablePrimesGenerationResult:
    """Encapsulates result of provable primes generation.
    This result includes status of generation, generated primes and parameters
    pSeed, qSeed, pGenCounter, qGenCounter used to verify generated primes.
    See FIPS 186-4 for details

    Attributes:
        status: bool
            True if generation was successful
            False if generation failed
        
        primes: Primes
            primes p and q. If status is False, this field is None
        
        verifyParams: ProvablePrimesGenerationResult.VerifyParams
            pSeed, qSeed, pGenCounter and qGenCounter for primes verification
    """
    
    class VerifyParams:
        """Encapsulates parameters for primes verification
        See FIPS 186-4 for details

        Attributes:
            firstSeed: int
            pSeed: int
            qSeed: int
            pGenCounter: int
            qGenCounter: int
        """

        def __init__(self, firstseed: int, pseed: int, qseed: int, pGenCounter:int, qGenCounter: int):
            """Initializes object with pSeed, qSeed, pGenCounter and qGenCounter

            Parameters:
                firstseed: int
                pseed: int
                qseed: int
                pGenCounter: int
                qGenCounter: int
            """

            self.firstSeed = firstseed
            self.pSeed = pseed
            self.qSeed = qseed
            self.pGenCounter = pGenCounter
            self.qGenCounter = qGenCounter
        
        def beautyRepr(self, level: int) -> str:
            """Returns object's beautified string representation

            Parameters:
                level: int
                    Indentation level
            """

            indent = "\t" * level
            return f"VerifyParams: \n{indent}pSeed: {hex(self.pSeed)}\n{indent}qSeed: {hex(self.qSeed)}\n{indent}pGenCounter: {hex(self.pGenCounter)}\n{indent}qGenCounter: {hex(self.qGenCounter)}"
    
    def __init__(self, status: bool, primes: Primes, verifyParams: VerifyParams):
        """Initializes object with status, primes, verifyParams

        Parameters:
            status: bool
                True if generation succeeded
                False if generation failed
            
            primes: Primes
                Generated prime numbers p and q
                This field is None if status is False
            
            verifyParams: ProvablePrimesGenerationResult.VerifyParams
                Parameters for primes verification
        """

        self.status = status
        self.primes = primes
        self.verifyParams = verifyParams
    
    def beautyRepr(self, level: int) -> str:
        """Returns object's beautified string representation

        Parameters:
            level: int
                Indentation level
        """

        indent = "\t" * level
        primesRepr = self.primes.beautyRepr(level + 1)
        verifyParamsRepr = self.verifyParams.beautyRepr(level + 1)

        return f"ProvablePrimesGenerationResult: \n{indent}status: {self.status}\n{indent}{primesRepr}\n{indent}{verifyParamsRepr}"


class PublicKey:
    """Encapsulates DSA public key

    Attributes:
        params: Params
            DSA parameters: p, q and g

        y: int
            Public exponent
    """

    def __init__(self, params: Params, y: int):
        """Initializes object with given params and public exponent
                
        Parameters:
            params: Params
                DSA parameters
            
            y: int
                Public exponent
        """

        self.params = params
        self.y = y


class PrivateKey:
    """Encapsulates DSA private key

    Attributes:
        params: Params
            DSA parameters: p, q and g
            
        x: int
            Private exponent
    """

    def __init__(self, params: Params, x: int):
        """Initializes object with given params and private exponent

        Parameters:
            params: Params
                DSA parameters
            
            x: int
                Private exponent
            """
        self.params = params
        self.x = x


class Signature:
    """Encapsulates DSA signature

    Attributes:
        params: Params
            DSA parameters: p, q and g
            
        r, s: int
            DSA signature pair
    """

    def __init__(self, params, r: int, s: int):
        """Initializes object with  given params and (r, s) pair

        Parameters:
            params: Params
                DSA parameters
                
            r: int
            s: int
        """
        self.params = params
        self.r = r
        self.s = s


def generateProbablePrimes(N: int, L: int, seedLength: int, hashFunction=hashlib.sha256) -> ProbablePrimesGenerationResult:
    """Generates probable primes p and q by algorithm from
    FIPS 186-4, Appendix A.1.1.2

    Parameters:
        N: int
            Bit length of q - smaller prime
            
        L: int
            Bit length of p - bigger prime
            
        seedLength: int
            Bit length of seed, must not be less than N
            
        hashFunction: callable
            Hash function conforming to hashlib protocols. By default hashlib.sha256 is used
            Hash function output length must not be less than N. 
            By FIPS 186-4 one of APPROVED_HASHES should be used
        
    Returns:
        result: ProbablePrimesGenerationResult
            Result of primes generation. result.status == False means something is wrong with
            passed parameters.
    """

    # Steps 1 and 2
    if (N, L) not in APPROVED_LENGTHS:
        return ProbablePrimesGenerationResult(False, None, None)
    if seedLength < N:
        ProbablePrimesGenerationResult(False, None, None)

    # Setting count of Miller-Rabin tests to perform before single Lucas test
    # according to Appendix C.3
    if (N, L) == APPROVED_LENGTHS[0]:
        pTests = 3
        qTests = 19
    elif (N, L) == APPROVED_LENGTHS[1]:
        pTests = 3
        qTests = 24
    elif (N, L) == APPROVED_LENGTHS[2]:
        pTests = 3
        qTests = 27
    else:
        pTests = 2
        qTests = 27

    # Length of hash funciton output in bits
    outlen = hashFunction().digest_size * 8
    if outlen < N:
        return ProbablePrimesGenerationResult(False, None, None)

    # Steps 3 and 4
    #   n = ceil(L / outlen) - 1
    if L % outlen == 0: n = L // outlen - 1
    else: n = L // outlen

    b = L - 1 - (n * outlen)

    # Some precalculated powers of two, so we dont calculate it on each iteration
    twoPowNMin1 = pow(2, N - 1)  # 2^(N - 1)
    twoPowSeedLength = pow(2, seedLength)  # 2^seedlen
    twoPowOutLength = pow(2, outlen)  # 2^outlen
    twoPowLMin1 = pow(2, L - 1)  # 2^(L - 1)
    twoPowB = pow(2, b)  # 2^b

    while 1:
        while 1:
            # Steps 5, 6, 7
            domainParameterSeed = random.getrandbits(seedLength) | 2 ** (seedLength - 1)

            #   U = Hash(domain_parameter_seed) mod 2^(N - 1)
            U = base.bytesToInt(hashFunction(base.intToBytes(domainParameterSeed)).digest()) % twoPowNMin1

            #   q = 2^(N - 1) + U + 1 - (U  mod 2)
            q = twoPowNMin1 + U + 1 - (U % 2)

            # Step 8
            if primality.millerRabin(q, qTests):
                if primality.lucasTest(q): break

        # Precalcualted value, to not calculate it in the loop
        twoTimesQ = 2 * q

        # Step 10
        offset = 1

        # Step 11
        for counter in range(0, 4 * L):

            # Steps 11.1 and 11.2
            W = 0
            for j in range(0, n):
                #   Vj = Hash((domain_parameter_seed + offset + j) mod 2^seedlen)
                hashPayload = base.intToBytes((domainParameterSeed + offset + j) % twoPowSeedLength)
                v = base.bytesToInt(hashFunction(hashPayload).digest())

                # W = sum(Vj * 2^(j * outlen))
                W += v * pow(twoPowOutLength, j)

            # Last term of W calculation
            #   Vj = Hash((domain_parameter_seed + offset + j) % 2^seedlen)
            hashPayload = base.intToBytes((domainParameterSeed + offset + n) % twoPowSeedLength)
            v = int(base.bytesToInt(hashFunction(hashPayload).digest()) % twoPowB)

            #   W += (Vn mod 2^b) * 2^(n * outlen)
            W += v * pow(twoPowOutLength, n)

            # Steps 11.3, 11.4 and 11.5
            X = W + twoPowLMin1
            c = X % twoTimesQ
            p = X - (c - 1)

            # Step 11.6
            if p >= twoPowLMin1:

                # Step 11.7
                if primality.millerRabin(p, pTests):
                    if primality.lucasTest(p):

                        # Step 11.8
                        primes = Primes(p, q)
                        verifyParams = ProbablePrimesGenerationResult.VerifyParams(domainParameterSeed, counter)

                        return ProbablePrimesGenerationResult(True, primes, verifyParams)

            # Step 11.9
            offset = offset + n + 1

    return ProbablePrimesGenerationResult(False, None, None)


def verifyProbablePrimesGenerationResult(result, hashFunction=hashlib.sha256) -> bool:
    """Verifies if primes were generated by algorithm from
    FIPS 186-4, Appendix A.1.1.2

    Note that verification takes at least as much time as generation

    Parameters:
        result: ProbablePrimesGenerationResult
            Value to be verified
            
        hashFunction: callable
            Hash function that conforms to hashlib protocols. 
            This function must be equal to the one used for primes generation
            By default hashlib.sha256 is used.
            By FIPS 186-4, one of APPROVED_HASHES should be used
            
    Returns:
        result: bool
            True if verification succeeds
            False if verification fails
    """

    p = result.primes.p
    q = result.primes.q
    domainParameterSeed = result.verifyParams.domainParameterSeed
    counter = result.verifyParams.counter

    # Steps 1, 2
    N = q.bit_length()
    L = p.bit_length()

    # Step 3
    if (N, L) not in APPROVED_LENGTHS: return False

    # Setting count of Miller-Rabin tests to perform before single Lucas test
    # according to Appendix C.3
    if (N, L) == APPROVED_LENGTHS[0]:
        pTests = 3
        qTests = 19
    elif (N, L) == APPROVED_LENGTHS[1]:
        pTests = 3
        qTests = 24
    elif (N, L) == APPROVED_LENGTHS[2]:
        pTests = 3
        qTests = 27
    else:
        pTests = 2
        qTests = 27

    # Step 4
    if counter > (4 * L - 1): return False

    # Steps 5, 6
    seedLength = domainParameterSeed.bit_length()
    if seedLength < N: return False

    # Precomputed value 2^(N - 1)
    twoPowNMin1 = pow(2, N - 1)

    # Step 7
    #   U = Hash(domain_parameter_seed) mod 2^(N - 1)
    hashPayload = base.intToBytes(domainParameterSeed)
    U = base.bytesToInt(hashFunction(hashPayload).digest()) % twoPowNMin1

    # Step 8
    #   computed_q = 2^(n - 1) + U + 1 - (U mod 2)
    computedQ = twoPowNMin1 + U + 1 - (U % 2)
    if computedQ != q: return False

    # Step 9
    if not primality.millerRabin(computedQ, qTests): return False
    if not primality.lucasTest(computedQ): return False

    outlen = hashFunction().digest_size * 8

    # Step 10
    #   n = ceil(L / outlen) - 1
    if L % outlen == 0: n = L // outlen - 1
    else: n = L // outlen

    # Step 11
    b = L - 1 - (n * outlen)

    # Some precalculated powers of two
    twoPowSeedLength = pow(2, seedLength)  # 2^seedlen
    twoPowOutLength = pow(2, outlen)  # 2^outlen
    twoPowLMin1 = pow(2, L - 1)  # 2^(L - 1)
    twoPowB = pow(2, b)  # 2^b
    twoTimesQ = 2 * q # 2 * q

    # Step 12
    offset = 1

    # Step 13
    for i in range(counter + 1):

        # Steps 13.1, 13.2
        W = 0
        for j in range(0, n):
            #   Vj = Hash((domain_parameter_seed + offset + j) mod 2^seedlen)
            hashPayload = base.intToBytes((domainParameterSeed + offset + j) % twoPowSeedLength)
            v = base.bytesToInt(hashFunction(hashPayload).digest())

            # W = sum(Vj * 2^(j * outlen))
            W += v * pow(twoPowOutLength, j)

        # Last term of W calculation
        #   Vj = Hash((domain_parameter_seed + offset + j) % 2^seedlen)
        hashPayload = base.intToBytes((domainParameterSeed + offset + n) % twoPowSeedLength)
        v = int(base.bytesToInt(hashFunction(hashPayload).digest()) % twoPowB)

        # W += Vn * 2^(outlen * n)
        W += v * pow(twoPowOutLength, n)

        # Steps 13.3, 13.4, 13.5
        X = W + twoPowLMin1
        c = X % twoTimesQ
        computed_p = X - (c - 1)

        # Step 13.6
        if computed_p < twoPowLMin1:
            offset = offset + n + 1
            continue

        # Step 13.7
        if primality.millerRabin(computed_p, pTests):
            if primality.lucasTest(computed_p):
                # Steps 14 and 15
                if i == counter and computed_p == p: return True
                else: return False

        # Step 13.9
        offset = offset + n + 1

    return False


def getFirstSeed(N: int, seedlen: int):
    """Generates first seed for provable primes generation

    Parameters:
        N: int
            Length of prime q in bits
        
        seedlen: int
            length of seed to return, must not be less than N
    
    Returns:
        firstSeed: int
            generated first seed or None if generation fails
    """

    firstSeed = 0
    
    nIsCorrect = False
    for lengths in APPROVED_LENGTHS:
        nIsCorrect = nIsCorrect or (N in lengths)
    
    if not nIsCorrect: return None
    if seedlen < N: return None

    twoPowNMin1 = pow(2, N - 1)
    while firstSeed < twoPowNMin1: 
        firstSeed = random.getrandbits(seedlen)
        firstSeed |= (2 ** (seedlen - 1) + 1)
    return firstSeed


def generateProvablePrimes(N: int, L: int, firstSeed: int, hashFunction: callable = hashlib.sha256) -> ProvablePrimesGenerationResult:
    """Generates provabele primes p and q by algorithm from
    FIPS 186-4, Appendix A.1.2.1.2

    Parameters:
        N: int
            Bit length of q - smaller prime
        
        L: int
            Bit length of p - bigger prime
        
        firstSeed: int
            the first seed to be used
        
        hashFunction: callable
            Hash function conforming to hashlib protocols.
            Hash function output length must not be less than N
            By FIPS 186-4 one of APPROVED_HASHES should be used
    
    Returns:
        result: ProvablePrimesGenerationResult
            Result of primes generation
    """

    # Step 1
    if (N, L) not in APPROVED_LENGTHS: return ProvablePrimesGenerationResult(False, None, None)
    
    # Step 2
    d = primality.shaweTaylorRandomPrime(N, firstSeed)
    if not d["status"]: return ProvablePrimesGenerationResult(False, None, None)

    q = d["prime"]
    qSeed = d["primeSeed"]
    qGenCounter = d["primeGenCounter"]

    # Step 3
    #   p0Length = ceil(L / 2 + 1)
    if L % 2 == 0: p0Length = L // 2 + 1
    else: p0Length = L // 2 + 2

    d = primality.shaweTaylorRandomPrime(p0Length, qSeed)
    if not d["status"]: return ProvablePrimesGenerationResult(False, None, None)

    p0 = d["prime"]
    pSeed = d["primeSeed"]
    pGenCounter = d["primeGenCounter"]

    outlen = hashFunction().digest_size * 8

    # Step 4, 5
    if L % outlen == 0: iterations = L // outlen - 1
    else: iterations = L // outlen

    oldCounter = pGenCounter

    twoPowOutlen = pow(2, outlen)
    twoPowLMin1 = pow(2, L - 1)

    # Steps 6, 7
    x = 0
    for i in range(iterations + 1):
        hashPayload = base.intToBytes(pSeed + i)
        h = base.bytesToInt(hashFunction(hashPayload).digest())

        x = x + h * pow(twoPowOutlen, i)
    
    # Steps 8, 9
    pSeed = pSeed + iterations + 1
    x = twoPowLMin1 + (x % twoPowLMin1)

    # Step 10
    #   t = ceil(x / (2 * q * p0))
    if x % (2 * q * p0) == 0: t = x // (2 * q * p0)
    else: t = x // (2 * q * p0) + 1

    while True:

        # Step 11
        if 2 * t * q * p0 + 1 > twoPowLMin1 * 2: t = twoPowLMin1 // (2 * q * p0) + (twoPowLMin1 % (2 * q * p0) != 0)

        # Steps 12, 13
        p = 2 * t * q * p0 + 1
        pGenCounter += 1

        # Steps 14, 15
        a = 0
        for i in range(iterations + 1):
            hashPayload = base.intToBytes(pSeed + i)
            h = base.bytesToInt(hashFunction(hashPayload).digest())

            a = a + h * pow(twoPowOutlen, i)
    
        # Steps 16, 17, 18
        pSeed = pSeed + iterations + 1
        a = 2 + (a % (p - 3))
        z = pow(a, 2 * t * q, p)

        # Step 19
        if 1 == base.gcd(z - 1, p) and 1 == pow(z, p0, p):
            primes = Primes(p, q)
            verifyParams = ProvablePrimesGenerationResult.VerifyParams(firstSeed, pSeed, qSeed, pGenCounter, qGenCounter)
            return ProvablePrimesGenerationResult(True, primes, verifyParams)
    
        # Step 20
        if pGenCounter > (4 * L + oldCounter): return ProvablePrimesGenerationResult(False, None, None)

        # Step 21
        t += 1


def verifyProvablePrimesGenerationResult(result: ProvablePrimesGenerationResult, hashFunction: callable=hashlib.sha256) -> bool:
    """Verifies if primes were generated by algorithm from
    FIPS 186-4, Appendix 1.2.1.2

    Note that verification takes at least as much time as generation

    Parameters:
        result: ProvablePrimesGenerationResult
            Value to be verified
        
        hashFunction: callable
            Hash function thath conforms to hashlib protocols.
            This function must be equal to the one used for primes generation
            By default hashlib.sha256 is used
            By FIPS 186-4, one of APPROVED_HASHES should be used

    Returns:
        result: bool
            True if verification succeeds
            False if verification fails
    """

    p = result.primes.p
    q = result.primes.q
    firstSeed = result.verifyParams.firstSeed
    pSeed = result.verifyParams.pSeed
    qSeed = result.verifyParams.qSeed
    pGenCounter = result.verifyParams.pGenCounter
    qGenCounter = result.verifyParams.qGenCounter

    L = p.bit_length()
    N = q.bit_length()

    if (N, L) not in APPROVED_LENGTHS: return False

    if firstSeed < pow(2, N - 1): return False
    if pow(2, N) <= q: return False
    if pow(2, L) <= p: return False
    if (p - 1) % q != 0: return False

    check = generateProvablePrimes(N, L, firstSeed, hashFunction)
    checkP = check.primes.p
    checkQ = check.primes.q
    checkPSeed = check.verifyParams.pSeed
    checkQSeed = check.verifyParams.qSeed
    checkPGenCounter = check.verifyParams.pGenCounter
    checkQGenCounter = check.verifyParams.qGenCounter

    if checkP != p: return False
    if checkQ != q: return False
    if checkPSeed != pSeed: return False
    if checkQSeed != qSeed: return False
    if checkPGenCounter != pGenCounter: return False
    if checkQGenCounter != qGenCounter: return False

    return True