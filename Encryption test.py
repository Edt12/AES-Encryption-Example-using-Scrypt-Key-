import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes

#1.Generate Key using Scrypt
#2.Make Cypher out of Key
#3.Make Decryptor out of Cypher to Decrypt
#4.Make Encryptor out of Cypher to Encrypt-Before it is encrypted data must be encoded 
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
    EncryptedData=Encryptor.update(Data)+Encryptor.finalize()#update encrypts finalize returns what it has encrypted same for decrypt
    return EncryptedData

Steve=Encrypt(Data="A secret message")#Has to be multiple of 128 for AES encryption to work will find a solution to this later

print(Decrypt(Steve))