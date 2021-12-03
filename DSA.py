import mathbase
import random
import hashlib


class DSA:

	class Signature:

		def __init__(self, params, r, s):
			self.params = params
			self.r = r
			self.s = s

	class Params:

		def __init__(self, biggerPrime, smallerPrime, g):
			self.biggerPrime = biggerPrime
			self.smallerPrime = smallerPrime
			self.g = g

	class PublicKey:

		def __init__(self, params, key):
			self.params = params
			self.key = key

	class PrivateKey:

		def __init__(self, params, key):
			self.params = params
			self.key = key

	def __init__(self, keyLength, primeLength):
		self.primeLength = primeLength
		self.keyLength = keyLength
		self.generateParams()
		self.generateKey()

	def generateParams(smallerLength, biggerLength):
	
		q = 0
		p = 0
		tries = 0
		while 1:
			tries += 1
			q = mathbase.getPrime(smallerLength)
			k = biggerLength - smallerLength
			p = (q << k) + 1
			if mathbase.isPrime(p, 10):
				print(p.bit_length())
				print(q.bit_length())
				print(f'Found params in {tries} tries')
				break
		i = 0
		k = mathbase.SMALL_PRIMES[i]
		g = pow(k, (p - 1) // q, p)
		while g == 1:
			i += 1
			if i >= len(mathbase.SMALL_PRIMES):
				return None

			k = mathbase.SMALL_PRIMES[i]
			g = pow(k, (p - 1) // q, p)

		return DSA.Params(p, q, g)


	def generateKeys(params):
		x = random.randint(1, params.smallerPrime - 1)
		y = pow(params.g, x, params.biggerPrime)
		publicKey = DSA.PublicKey(params, y)
		privateKey = DSA.PrivateKey(params, x)
		return (publicKey, privateKey)


	def sign(m, key):
		r = 0
		s = 0
		while r == 0 or s == 0:
			k = random.randint(1, key.params.smallerPrime - 1)
			r = pow(key.params.g, k, key.params.biggerPrime) % key.params.smallerPrime
			s = pow(k, -1, key.params.smallerPrime) * (m + key.key * r) % key.params.smallerPrime
		return DSA.Signature(params, r, s)


	def verify(m, signature, key):
		w = pow(signature.s, -1, key.params.smallerPrime)
		u1 = w * m % key.params.smallerPrime
		u2 = w * signature.r % key.params.smallerPrime
		v = (pow(key.params.g, u1, key.params.biggerPrime) * pow(key.key, u2, key.params.biggerPrime) % key.params.biggerPrime) % key.params.smallerPrime
		return v == signature.r


upperBound = 2 ** 99 - 1
m = random.randint(1, upperBound)
params = DSA.generateParams(512, 1024)
(public, private) = DSA.generateKeys(params)
signature = DSA.sign(m, private)
assert DSA.verify(m, signature, public)
print(f"Check done")