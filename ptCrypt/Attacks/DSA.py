from ptCrypt.Asymmetric import DSA


def repeatedSecretAttack(
    message1: any,
    signature1: DSA.Signature, 
    message2: any,
    signature2: DSA.Signature,
    hashFunction: callable
) -> DSA.PrivateKey:
    """This attack requires two distinct messages and their signatures. 
    If two messages were signed with same private key and same secret value, 
    this function will return valid private key for DSA.

    Note that function can receive messages either as integer values, or as bytes.
    If bytes are passed, they will be processed into integers according to FIPS 186-4, 
    i.e. with DSA.prepareMessage function.

    Note also, that if messages are passed as integers, then hash function does not affect anything

    Parameters:
        message1: bytes
            first message
        
        signature1: DSA.Signature
            first message's signature
        
        message2: bytes
            second message
        
        signature2: DSA.Signature
            second message's signature

    Returns:
        result: DSA.PrivateKey
            Recovered private key or None, if the attack has failed
    """

    s1 = signature1.s
    s2 = signature2.s

    r = signature1.r
    q = signature1.params.primes.q

    if type(message1) is bytes:
        message1 = DSA.prepareMessage(message1, signature1.params, hashFunction)
    
    if type(message2) is bytes:
        message2 = DSA.prepareMessage(message2, signature2.params, hashFunction)

    diff = pow((s1 - s2) % q, -1, q)
    hashDiff = (message1 - message2) % q

    k = (hashDiff * diff) % q
    
    rInv = pow(r, -1, q)
    x1 = (rInv * (s1 * k - message1)) % q
    x2 = (rInv * (s2 * k - message2)) % q

    if x1 == x2: return DSA.PrivateKey(signature1.params, x1)
    else: return None
