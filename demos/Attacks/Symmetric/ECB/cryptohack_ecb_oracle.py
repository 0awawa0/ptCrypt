from ptCrypt.Attacks.Symmetric.ECB.EcbEncryptionOracleAppendAttack import EcbEncryptionOracleAppendAttack
import requests
import json
from time import sleep

baseAddress = "https://aes.cryptohack.org/ecb_oracle/encrypt/"

def query(payload: bytes):
    # The server may refuse connection due to too many calls, in that case, we wait a few seconds and try sending again
    while True:
        try:
            request = baseAddress + payload.hex()
            response = requests.get(request)
            
            ciphertext = json.loads(response.content)["ciphertext"]
            return bytes.fromhex(ciphertext)
        except:
            sleep(10)
    

print("Found flag: " + EcbEncryptionOracleAppendAttack(blockSize = 16, query = query, searchRange=range(32, 128)).run().decode())