# Math

## [base](./base.py)

Contains the following algorihtms (read documentation in the file for more information about each function):

1. `gcd()` - Euklidean algorithm

2. `egcd()` - Extended Euklidean algorithm.

3. `isPerfectSquare()` - determines if an integer is a square of another integer.

4. `jacobiSymbol()` - calculates Jacobi symbol

5. `eulersTotient()` - calculates Euler's function for given integer.

6. `iroot()` - calculates integer `a`-th integer root for number `b`.

7. `intToBytes()` - converts integer into bytes.

8. `byteLength()` - returns minimal amount of bytes to store given integer.

9. `bytesToInt()` - converts bytes to integer

10. `pad()` - pads data to required length.

11. `partition()` - partitions byte string into list of byte strings of given length.

12. `xor()` - XORes two bytes strings.

13. `getRandomBytes()` - generates random byte string of required length.

14. `crt()` - Chinese remainder theorem implementaiton.

15. `getGenerator()` - calculates generator of subgroup of order `q` in the finite group modulo `p`.

16. `getPrimitiveRoot()` - calculates primitive root modulo prime number `p`.

17. `continuedFraction()` - calculates representation of number `a / b` as a continued fraction.

18. `getConvergents()` - calculates convergents of the continued fraction.

## [primality](./primality.py)

Contains various algorithms related to prime numbers:

1. `millerRabin()` - Miller-Rabin primality test.

2. `lucasTest()` - Lucas pseudoprime primality test.

3. `trialDivisionTest()` - primality test by trial division.

4. `getPrime()` - generates prime number of given bit length.

5. `primeFactors()` - finds prime factors of an integer.

6. `pollardFactor()` - Pollard's p - 1 factorization algorithm.

7. `shaweTaylor()` - Shawe-Taylor prime generation algorithm.

8. `lenstraFactor()` - Lenstra's EC factorization algorithm.

9. `ifcProvablePrime()` - generates provable primem for integer factorization cryptography algorithms.

10. `getFfcPrimes()` - generates pair of primes for finite field cryptography algorithms.

11. `getProbablePrimesForFfc()` - generates pair of probable primes for finite field cryptography algorithms.

12. `getProvablePrimesForFFC()` - generates pair of provable primes for FFC algorithms.

## [smallPrimes](./smallPrimes.py)

Contains the single variable `SMALL_PRIMES` - list of all primes less than `1,000,000`. There are `78498` primes in the list.