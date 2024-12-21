import pwn
import json
from ptCrypt.Attacks.Symmetric.CBC.CbcPkcs7PaddingOracleAttack import CbcPkcs7PaddingOracleAttack


address = ("socket.cryptohack.org", 13421)
connection = pwn.connect(address[0], address[1])
connection.recvline()


def createEncryptCommand() -> str:
    return "{\"option\":\"encrypt\"}"

def createUnpadCommand(ct: str) -> str:
    return "{\"option\":\"unpad\",\"ct\":\"" + ct + "\"}"


def createCheckCommand(message: str) -> str:
    return "{\"option\":\"check\",\"message\":\"" + message + "\"}"


def checkPadding(message: bytes) -> bool:
    messageHex = message.hex()
    command = createUnpadCommand(messageHex)
    connection.sendline(command.encode())
    result = json.loads(connection.recvline().decode())["result"]
    return result


def isAppropriate(value: int) -> bool:
    return chr(value) in "0123456789abcdef"


class ListenerImpl(CbcPkcs7PaddingOracleAttack.Listener):

    def attackStarted(self):
        print("Attack started")
    
    
    def attackFinished(self, foundText):
        print("Attack finished. Found text: " + foundText.hex())
    

    def foundValue(self, position, value, totalCount):
        print("Found value for position " + str(position) + ": " + str(value) + ". Total length: " + str(totalCount))

    
    def failedToFind(self, position):
        print("Failed to find value at position " + str(position))


command = createEncryptCommand()
connection.sendline(command.encode())
ciphertext = bytes.fromhex(json.loads(connection.recvline().decode())["ct"])

attack  = CbcPkcs7PaddingOracleAttack(
    blockSize=16, 
    encryptedMessage=ciphertext, 
    checkPadding=checkPadding, 
    isAppropriate=isAppropriate,
    listener=ListenerImpl()
)
message = attack.run()

command = createCheckCommand(message.decode())
connection.sendline(command.encode())
print(connection.recvline().decode())