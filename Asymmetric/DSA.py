import mathbase
import random
import hashlib
import math


class DSA:

	APPROVED_LENGTHS = [
		(160, 1024),
		(224, 2048),
		(256, 2048),
		(256, 3072)
	]

	class Params:

		class Primes:
			def __init__(self, p: int, q: int):
				self.p = p
				self.q = q
			
			def beautyRepr(self, level: int) -> str:
				indent = "\t" * level
				return f"Primes: \n{indent}p: {hex(self.p)}\n{indent}q: {hex(self.q)}"


		class ProbablePrimesGenerationResult:
			class ProbablePrimesVerifyParams:
				def __init__(self, domainParameterSeed: int, counter: int):
					self.domainParameterSeed = domainParameterSeed
					self.counter = counter
				
				def beautyRepr(self, level: int) -> str:
					indent = "\t" * level
					return f"ProbablePrimesVerifyParams:\n{indent}domainPrameterSeed: {hex(self.domainParameterSeed)}\n{indent}counter: {hex(self.counter)}"
			
			def __init__(self, status: bool, primes, verifyParams: ProbablePrimesVerifyParams):
				self.status = status
				self.primes = primes
				self.verifyParams = verifyParams

			def beautyRepr(self, level: int) -> str:
				primesRepr = self.primes.beautyRepr(level + 1)
				verifyParamsRepr = self.verifyParams.beautyRepr(level + 1)
				indent = "\t" * level
				return f"ProbablePrimesGenerationResult: \n{indent}status: {self.status}\n{indent}{primesRepr}\n{indent}{verifyParamsRepr}"
			
		def __init__(self, primes: Primes, g: int):
			self.primes = primes
			self.g = g

		def beautyRepr(self, level: int) -> str:
			primesRepr = self.primes.beautyRepr(level + 1)
			indent = "\t" * level
			return f"DSA Params: \n{indent}{primesRepr}\n{indent}g: {self.g}"

	class PublicKey:

		def __init__(self, params, y: int):
			self.params = params
			self.y = y

	class PrivateKey:

		def __init__(self, params, x: int):
			self.params = params
			self.x = x
	
	class Signature:

		def __init__(self, params, r: int, s: int):
			self.params = params
			self.r = r
			self.s = s

	def generateProbablePrimes(N: int, L: int, seedLength: int, hashFunction=hashlib.sha256):

		if (N, L) not in DSA.APPROVED_LENGTHS: return DSA.Params.ProbablePrimesGenerationResult(False, None, None)
		if seedLength < N: DSA.Params.ProbablePrimesGenerationResult(False, None, None)

		# Length of hash funciton output in bits
		outlen = hashFunction().digest_size * 8
		if outlen < N: return DSA.Params.ProbablePrimesGenerationResult(False, None, None)

		if L % outlen == 0:
			n = L // outlen - 1
		else:
			n = L // outlen
		
		b = L - 1 - (n * outlen)

		twoPowNMin1 = pow(2, N - 1)
		twoPowSeedLength = pow(2, seedLength)
		twoPowOutLength = pow(2, outlen)
		twoPowLMin1 = pow(2, L - 1)
		twoPowB = pow(2, b)

		while 1:

			while 1:
				domainParameterSeed = random.getrandbits(seedLength)
				U = mathbase.bytesToInt(hashFunction(mathbase.intToBytes(domainParameterSeed)).digest()) % twoPowNMin1
				q = twoPowNMin1 + U + 1 - (U % 2)
				if mathbase.isPrime(q, 10):
					break

			twoTimesQ = 2 * q

			offset = 1
			for counter in range(0, 4 * L - 1):
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
				p = X - (c - 1)
				if p >= twoPowLMin1:
					if mathbase.isPrime(p, 10):
						primes = DSA.Params.Primes(p, q)
						verifyParams = DSA.Params.ProbablePrimesGenerationResult.ProbablePrimesVerifyParams(domainParameterSeed, counter)
						return DSA.Params.ProbablePrimesGenerationResult(True, primes, verifyParams)
				offset = offset + n + 1

		return DSA.Params.ProbablePrimesGenerationResult(False, None, None)

	def verifyProbablePrimesGenerationResult(result, hashFunction=hashlib.sha256) -> bool:
		p = result.primes.p
		q = result.primes.q
		domainParameterSeed = result.verifyParams.domainParameterSeed
		counter = result.verifyParams.counter

		N = q.bit_length()
		L = p.bit_length()
		if (N, L) not in DSA.APPROVED_LENGTHS: 
			print(1)
			return False

		if counter > (4 * L - 1): 
			print(2)
			return False

		seedLength = domainParameterSeed.bit_length()
		if seedLength < N: 
			print(3)
			return False

		twoPowNMin1 = pow(2, N - 1)
		hashPayload = mathbase.intToBytes(domainParameterSeed)
		U = mathbase.bytesToInt(hashFunction(hashPayload).digest()) % twoPowNMin1
		computedQ = pow(2, N - 1) + U + 1 - (U % 2)
		if computedQ != q or (not mathbase.isPrime(computedQ, 10)):
			print(4)
			return False
		
		outlen = hashFunction().digest_size * 8
		if L % outlen == 0:
			n = L // outlen - 1
		else:
			n = L // outlen
		
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
				
			if mathbase.isPrime(computed_p, 10):
				if i == counter and computed_p == p:
					return True
				else:
					print(5)
					return False
			
			offset = offset + n + 1

		print(6)
		return False

	def generateKeys(params: Params):
		x = random.randint(1, params.q - 1)
		y = pow(params.g, x, params.p)
		publicKey = DSA.PublicKey(params, y)
		privateKey = DSA.PrivateKey(params, x)
		return (publicKey, privateKey)


	def sign(m: int, key: PrivateKey):
		r = 0
		s = 0
		while r == 0 or s == 0:
			k = random.randint(1, key.params.q - 1)
			r = pow(key.params.g, k, key.params.p) % key.params.q
			s = pow(k, -1, key.params.q) * (m + key.x * r) % key.params.q
		return DSA.Signature(params, r, s)


	def verify(m: int, signature: Signature, key: PublicKey):
		w = pow(signature.s, -1, key.params.q)
		u1 = w * m % key.params.q
		u2 = w * signature.r % key.params.q
		v = (pow(key.params.g, u1, key.params.p) * pow(key.y, u2, key.params.p) % key.params.p) % key.params.q
		return v == signature.r
