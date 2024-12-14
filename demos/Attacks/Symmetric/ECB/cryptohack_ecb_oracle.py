from ptCrypt.Attacks.Symmetric.ECB.EcbEncryptionOracleAppendAttack import EcbEncryptionOracleAppendAttack
import requests
import json
from time import sleep

baseAddress = "https://aes.cryptohack.org/ecb_oracle/encrypt/"

class AttackListener(EcbEncryptionOracleAppendAttack.Listener):

    def __init__(self):
        self.knownPlaintext = ""

    def attackStarted(self):
        print("Started searching plaintext")

    def foundValue(self, position, value, targetLength):
        self.knownPlaintext += chr(value)
        print(self.knownPlaintext)

    def attackFinished(self, foundText):
        print("Finished the attack. Found plaintext: " + foundText.decode())

    def failedToFind(self, position):
        print("Did not find byte at position " + str(position))


def query(payload: bytes):
    while True:
        try:
            request = baseAddress + payload.hex()
            response = requests.get(request)

            ciphertext = json.loads(response.content)["ciphertext"]
            return bytes.fromhex(ciphertext)
        except:
            sleep(10)
    

attack = EcbEncryptionOracleAppendAttack(
    blockSize = 16, 
    query = query, 
    listener = AttackListener(), 
    searchStart = 32, 
    searchEnd = 127,
    knownText=b""
)

attack.run()