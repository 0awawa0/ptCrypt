# ptCrypt

<a href="https://imgflip.com/i/5wzuke"><img src="https://i.imgflip.com/5wzuke.jpg" title="made at imgflip.com"/></a><div><a href="https://imgflip.com/memegenerator"></a></div>

## Description
Library contains implementations of popular cryptographic algorithms and also some cryptanalytic attacks on those algorithms. The implementations follow the standards, so they should be safe enough against modern cryptanalytic techniques. __BUT it is strongly NOT recommended to use this library for real world encryption.__ Instead, consider using more popular, reviewed and tested libraries. First of all, despite that the algorithms were implemented according to official standards, there is no guarantee that code doesn't contain any mistakes (aka possible security threats). And the second reason is that library contains 100% Python code and only uses standard library dependencies, so it is a lot slower than other libraries. The library never meant to be replacement for popular crypto libraries for real-world applications.

However, because of it uses only Python code and it doesn't have any dependencies except standard Python library this package doesn't have any installation issues as other libraries have (PyCrypto, for example might have some troubles during installation and configuration). Also, this library contains cryptanalytic attacks implementations, that might be useful for hackers' competitions, like CTFs.

## [Project structure](./ptCrypt/README.md)

## Attacks included in the library

### RSA
1. Private key factorization: finds divisor of RSA modulus (`N`), using private and public exponents (`d` and `e`).
2. Common modulus attack: decrypts message that was encrypted with different public exponents (`E1`, `E2`) but the same modulus (`N`).
3. Wiener attack (Attack on small private exponent): finds private exponent (`d`) if `d < (N^0.25) / 3`, e.g. if `d` is small. Attack uses `N` and `e`.
4. Hastad attack (Attack on small public exponent): decrypts message that was encrypted with different moduluses but the same __small__ public exponent.

### DSA
1. Repeated secret nonce attack: finds private key from two different signatures that used same parameters, including secret nonce.

More attacks are to be added in future.

### CBC encryption mode
1. [PKCS 7 padding oracle attack](./ptCrypt/Attacks/Symmetric/CBC/CbcPkcs7PaddingOracleAttack.py)
 
    Attack on a block cipher working in CBC encryption mode with PKCS7 padding. Applicable when you have an encrypted message, which you can change and check padding on that message.

### ECB encryption mode
1. [Encryption oracle attack](./ptCrypt/Attacks/Symmetric/ECB/EcbEncryptionOracleAppendAttack.py)
    
    Attack on a block cipher working in ECB encryption mode. Applicable when you have an oracle that allows you to encrypt arbitrary text and appends secret information to your message.
    Let's call secret part 'x', then this attack would be applicable if you can send value 'y' and oracle actually encrypts value 'yx' and sends
    encrypted text back to you.
    Then you can ecnrypt different values of 'y' in such a way that you can infer 'x' byte by byte.

### RC4
1. [Fluhrer-Mantin-Shamir attack](./ptCrypt/Attacks/Symmetric/RC4/FluhrerMantinShamirAttack.py)

    Attack on RC4 stream cipher with at least 3 byte long IV prepended to the encryption key.