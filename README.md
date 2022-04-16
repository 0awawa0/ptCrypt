# ptCrypt

<a href="https://imgflip.com/i/5wzuke"><img src="https://i.imgflip.com/5wzuke.jpg" title="made at imgflip.com"/></a><div><a href="https://imgflip.com/memegenerator"></a></div>

## Description
Library contains implementations of popular cryptographic algorithms and also some cryptanalytic attacks on those algorithms. The implementations follow the standards, so they should be safe enough against modern cryptanalytic techniques. __BUT it is strongly NOT recommended to use this library for real world encryption.__ Instead, consider using more popular, reviewed and tested libraries. First of all, despite that the algorithms were implemented according to official standards, there is no guarantee that code doesn't contain any mistakes (aka possible security threats). And the second reason is that library contains 100% Python code and only uses standard library dependencies, so it is a lot slower than other libraries. The library never meant to be replacement for popular crypto libraries for real-world applications.

However, because of it uses only Python code and it doesn't have any dependencies except standard Python library this package doesn't have any installation issues as other libraries have (PyCrypto, for example might have some troubles during installation and configuration). Also, this library contains cryptanalytic attacks implementations, that might be useful for hackers' competitions, like CTFs.

## [Project structure](./ptCrypt/README.md)

## Attacks included in library

### RSA
1. Private key factorization: finds divisor of RSA modulus (`N`), using private and public exponents (`d` and `e`).
2. Common modulus attack: decrypts message that was encrypted with different public exponents (`E1`, `E2`) but the same modulus (`N`).
3. Wiener attack (Attack on small private exponent): finds private exponent (`d`) if `d < (N^0.25) / 3`, e.g. if `d` is small. Attack uses `N` and `e`.
4. Hastad attack (Attack on small public exponent): decrypts message that was encrypted with different moduluses but the same __small__ public exponent.

### DSA
1. Repeated secret nonce attack: finds private key from two different signatures that used same parameters, including secret nonce.

More attacks are to be added in future.
