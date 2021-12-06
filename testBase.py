import mathbase
from datetime import datetime
import random


def measurePrimalityTestTime():
    t = []
    t1 = []
    count = 0
    for _ in range(10):
        prime = random.getrandbits(2048)

        start = datetime.now()
        a = mathbase.isPrime(prime, 10)
        end = datetime.now()
        t.append((end - start).microseconds)

        start = datetime.now()
        b = mathbase.isPrimeOld(prime, 10)
        end = datetime.now()
        t1.append((end - start).microseconds)

        assert a == b
        if a:
            count += 1


    avg = sum(t) / len(t)
    avg1 = sum(t1) / len(t1)
    print(f"Avg time: {avg}")
    print(f"Avg time: {avg1}")
    print(f"Enhance: {avg1 / avg}")
    print(f"Count of primes: {count}")


if __name__ == "__main__":
    