import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes


def GenerateKey(UsernameAndPassword):
    salt=os.urandom(16)
    iv=os.urandom(16)
    KeyDerivationFunction=Scrypt(salt=salt,length=32,n=2**20,r=8,p=1)
    UsernameAndPassword=str(UsernameAndPassword).encode()
    Key=KeyDerivationFunction.derive(UsernameAndPassword)
    cipher=Cipher(algorithms.AES(Key),modes.CBC(iv))
    return cipher


cipher=GenerateKey(UsernameAndPassword="steve")

def Decrypt(Data):
        Decryptor=cipher.decryptor()
        DecryptedData=Decryptor.update(Data)+Decryptor.finalize()
        return DecryptedData

def Encrypt(Data):
    Encryptor=cipher.encryptor()
    Data=Data.encode()
    EncryptedData=Encryptor.update(Data)+Encryptor.finalize()
    return EncryptedData

Steve=Encrypt(Data="A secret message")

print(Decrypt(Steve))