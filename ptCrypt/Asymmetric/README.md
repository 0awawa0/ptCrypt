# Asymmetric

## [DSA](./DSA.py)

Contains algorithms for digital signature algorithm impelementation from FIPS 186-4. As the standard specifies different algorithms for same operations, there is no ready-to-go implementation of DSA in the module right now. Instead, you can compose the most appropriate implementation for your use case from given building blocks.


## [RSA](./RSA.py)

Contains algorithms for RSA algorithm implementation from FIPS 186-4. The standard specifies different ways to implement same operations, so the module does not contain ready-to-go implementation of RSA. Instead, you can compose the most appropriate implementation for your use case from given building blocks. However, there is a simple `getParameters(N: int)` function, that will generate RSA parameters using just the required modulus size `N`. It will use different algorithms depending on the required modulus size to compromise between parameters security and generation speed.

The file also contains implementations of algorithms from PKCS#1, including RSA-OAEP and RSA-PKCS1v1.5 encryption schemes and RSASSA-PSS and RSASSA-PKCS1v1.5 signature schemes.

# [ECC](./ECC/README.md)

Module with elliptic curve cryptography implementations.