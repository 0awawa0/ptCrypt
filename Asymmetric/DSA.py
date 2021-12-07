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
    """Generates probable primes p and q by FIPS 186-4 algorithm

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

    if (N, L) not in APPROVED_LENGTHS:
        return ProbablePrimesGenerationResult(False, None, None)
    if seedLength < N:
        ProbablePrimesGenerationResult(False, None, None)

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

    n = L // outlen + ((L & 1) - 1)
    # if L % outlen == 0:
    #     n = L // outlen - 1
    # else:
    #     n = L // outlen

    b = L - 1 - (n * outlen)

    twoPowNMin1 = pow(2, N - 1)
    twoPowSeedLength = pow(2, seedLength)
    twoPowOutLength = pow(2, outlen)
    twoPowLMin1 = pow(2, L - 1)
    twoPowB = pow(2, b)

    x = []
    while 1:
        while 1:
            domainParameterSeed = random.getrandbits(seedLength)
            U = mathbase.bytesToInt(hashFunction(mathbase.intToBytes(domainParameterSeed)).digest()) % twoPowNMin1
            q = twoPowNMin1 + U + (1 - U % 2)
            if mathbase.millerRabin(q, qTests):
                if mathbase.lucasTest(q): break

        twoTimesQ = 2 * q

        offset = 1
        for counter in range(0, 4 * L - 1):

            W = 0
            for j in range(0, n):
                hashPayload = mathbase.intToBytes((domainParameterSeed + offset + j) % twoPowSeedLength)
                v = mathbase.bytesToInt(hashFunction(hashPayload).digest())
                W += v * pow(twoPowOutLength, j)

            hashPayload = mathbase.intToBytes((domainParameterSeed + offset + n) % twoPowSeedLength)
            v = int(mathbase.bytesToInt(
            hashFunction(hashPayload).digest()) % twoPowB)
            W += v * pow(twoPowOutLength, n)

            
            X = W + twoPowLMin1
            c = X % twoTimesQ
            p = X - (c - 1)

            if p >= twoPowLMin1:
                if mathbase.millerRabin(p, pTests):
                    if mathbase.lucasTest(p):
                        primes = Primes(p, q)
                        verifyParams = ProbablePrimesGenerationResult.VerifyParams(domainParameterSeed, counter)

                        return ProbablePrimesGenerationResult(True, primes, verifyParams)

            offset = offset + n + 1

    return ProbablePrimesGenerationResult(False, None, None)

def verifyProbablePrimesGenerationResult(result, hashFunction=hashlib.sha256) -> bool:
    """Verifies if primes were generated by FIPS 186-4 algorithm
    See FIPS 186-4 for algorithm details


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

    N = q.bit_length()
    L = p.bit_length()
    if (N, L) not in APPROVED_LENGTHS:
        return False

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

    if counter > (4 * L - 1):
        return False

    seedLength = domainParameterSeed.bit_length()
    if seedLength < N:
        return False

    twoPowNMin1 = pow(2, N - 1)
    hashPayload = mathbase.intToBytes(domainParameterSeed)
    U = mathbase.bytesToInt(hashFunction(hashPayload).digest()) % twoPowNMin1
    computedQ = pow(2, N - 1) + U + 1 - (U % 2)
    if computedQ != q: return False
    if not mathbase.millerRabin(computedQ, qTests): return False
    if not mathbase.lucasTest(computedQ): return False

    outlen = hashFunction().digest_size * 8
    if L % outlen == 0: n = L // outlen - 1
    else: n = L // outlen

    b = L - 1 - (n * outlen)
    twoPowSeedLength = pow(2, seedLength)
    twoPowOutLength = pow(2, outlen)
    twoPowLMin1 = pow(2, L - 1)
    twoPowB = pow(2, b)
    offset = 1

    twoTimesQ = 2 * q
    for i in range(counter + 1):
        W = 0
        for j in range(0, n):
            hashPayload = mathbase.intToBytes((domainParameterSeed + offset + j) % twoPowSeedLength)
            v = mathbase.bytesToInt(hashFunction(hashPayload).digest())
            W += v * pow(twoPowOutLength, j)

        hashPayload = mathbase.intToBytes((domainParameterSeed + offset + n) % twoPowSeedLength)
        v = int(mathbase.bytesToInt(hashFunction(hashPayload).digest()) % twoPowB)
        W += v * pow(twoPowOutLength, n)

        X = W + twoPowLMin1
        c = X % twoTimesQ
        computed_p = X - (c - 1)
        if computed_p < twoPowLMin1:
            offset = offset + n + 1
            continue

        if mathbase.millerRabin(computed_p, pTests):
            if mathbase.lucasTest(computed_p):
                if i == counter and computed_p == p:
                    return True
                else:
                    return False

        offset = offset + n + 1

    return False

