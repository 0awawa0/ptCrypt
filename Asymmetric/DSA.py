import mathbase
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
        """Prints out the object in a beautified way

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
        """Prints out the object in a beautified way

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
                
        verifyParams: ProbablePrimesVerifyParams
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
            """Prints out the object in a beautified way

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
                    
            verifyParams: ProbablePrimesVerifyParams
                Parameters for primes verification
        """

        self.status = status
        self.primes = primes
        self.verifyParams = verifyParams

    def beautyRepr(self, level: int) -> str:
        """Prints out the object in a beautified way

        Parameters:
            level: int
                Indentation level
        """

        primesRepr = self.primes.beautyRepr(level + 1)
        verifyParamsRepr = self.verifyParams.beautyRepr(level + 1)
        indent = "\t" * level
        return f"ProbablePrimesGenerationResult: \n{indent}status: {self.status}\n{indent}{primesRepr}\n{indent}{verifyParamsRepr}"


class ProvablePrimesGenerationResult:
    """
    """
    
    class VerifyParams:

        def __init__(self, pseed: int, qseed: int, pgenCounter:int, qgenCounter: int):
            self.pseed = pseed
            self.qseed = qseed
            self.pgenCounter = pgenCounter
            self.qgenCounter = qgenCounter
        
        def beautyRepr(self, level: int) -> str:
            pass
    
    def __init__(self, status: bool, primes: Primes, verifyParams: VerifyParams):

        self.status = status
        self.primes = primes
        self.verifyParams = verifyParams
    
    def beautyRepr(self, level: int) -> str:
        pass


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
    if L % outlen: n = L // outlen - 1
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
            domainParameterSeed = random.getrandbits(seedLength)

            #   U = Hash(domain_parameter_seed) mod 2^(N - 1)
            U = mathbase.bytesToInt(hashFunction(mathbase.intToBytes(domainParameterSeed)).digest()) % twoPowNMin1

            #   q = 2^(N - 1) + U + 1 - (U  mod 2)
            q = twoPowNMin1 + U + 1 - (U % 2)

            # Step 8
            if mathbase.millerRabin(q, qTests):
                if mathbase.lucasTest(q): break

        # Precalcualted value, to not calculate it in the loop
        twoTimesQ = 2 * q

        # Step 10
        offset = 1

        # Step 11
        for counter in range(0, 4 * L - 1):

            # Steps 11.1 and 11.2
            W = 0
            for j in range(0, n):
                #   Vj = Hash((domain_parameter_seed + offset + j) mod 2^seedlen)
                hashPayload = mathbase.intToBytes((domainParameterSeed + offset + j) % twoPowSeedLength)
                v = mathbase.bytesToInt(hashFunction(hashPayload).digest())

                # W = sum(Vj * 2^(j * outlen))
                W += v * pow(twoPowOutLength, j)

            # Last term of W calculation
            #   Vj = Hash((domain_parameter_seed + offset + j) % 2^seedlen)
            hashPayload = mathbase.intToBytes((domainParameterSeed + offset + n) % twoPowSeedLength)
            v = int(mathbase.bytesToInt(hashFunction(hashPayload).digest()) % twoPowB)

            #   W += (Vn mod 2^b) * 2^(n * outlen)
            W += v * pow(twoPowOutLength, n)

            # Steps 11.3, 11.4 and 11.5
            X = W + twoPowLMin1
            c = X % twoTimesQ
            p = X - (c - 1)

            # Step 11.6
            if p >= twoPowLMin1:

                # Step 11.7
                if mathbase.millerRabin(p, pTests):
                    if mathbase.lucasTest(p):

                        # Step 11.8
                        primes = Primes(p, q)
                        verifyParams = ProbablePrimesGenerationResult.VerifyParams(domainParameterSeed, counter)

                        return ProbablePrimesGenerationResult(True, primes, verifyParams)

            # Step 11.9
            offset = offset + n + 1

    return ProbablePrimesGenerationResult(False, None, None)

def verifyProbablePrimesGenerationResult(result, hashFunction=hashlib.sha256) -> bool:
    """Verifies if primes were generated algorithm from
    FIPS 186-4, Appendix A.1.1.3


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
    hashPayload = mathbase.intToBytes(domainParameterSeed)
    U = mathbase.bytesToInt(hashFunction(hashPayload).digest()) % twoPowNMin1

    # Step 8
    #   computed_q = 2^(n - 1) + U + 1 - (U mod 2)
    computedQ = twoPowNMin1 + U + 1 - (U % 2)
    if computedQ != q: return False

    # Step 9
    if not mathbase.millerRabin(computedQ, qTests): return False
    if not mathbase.lucasTest(computedQ): return False

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
            hashPayload = mathbase.intToBytes((domainParameterSeed + offset + j) % twoPowSeedLength)
            v = mathbase.bytesToInt(hashFunction(hashPayload).digest())

            # W = sum(Vj * 2^(j * outlen))
            W += v * pow(twoPowOutLength, j)

        # Last term of W calculation
        #   Vj = Hash((domain_parameter_seed + offset + j) % 2^seedlen)
        hashPayload = mathbase.intToBytes((domainParameterSeed + offset + n) % twoPowSeedLength)
        v = int(mathbase.bytesToInt(hashFunction(hashPayload).digest()) % twoPowB)

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
        if mathbase.millerRabin(computed_p, pTests):
            if mathbase.lucasTest(computed_p):
                # Steps 14 and 15
                if i == counter and computed_p == p: return True
                else: return False

        # Step 13.9
        offset = offset + n + 1

    return False


def getFirstSeed(N: int, seedlen: int):
    firstSeed = 0
    
    nIsCorrect = False
    for lengths in APPROVED_LENGTHS:
        nIsCorrect = nIsCorrect or (N in lengths)
    
    if not nIsCorrect: return None
    if seedlen < N: return None

    twoPowNMin1 = pow(2, N - 1)
    while firstSeed < twoPowNMin1: random.getrandbits(seedlen)
    return firstSeed

def generateProvablePrimes(L: int, N: int, firstSeed: int) -> ProvablePrimesGenerationResult:

    if (L, N) not in APPROVED_LENGTHS: return ProvablePrimesGenerationResult(False, None, None)
    