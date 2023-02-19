import os
import base64
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet

#1.Generate Key using Scrypt
#2.Put Key into Fernet
#padding built in 
def GenerateKey(UsernameAndPassword):
    salt=os.urandom(32)
    KeyDerivationFunction=Scrypt(salt=salt,length=32,n=2**20,r=8,p=1)
    UsernameAndPassword=str(UsernameAndPassword).encode()
    Key=base64.urlsafe_b64encode(KeyDerivationFunction.derive(UsernameAndPassword))
    cipher=Fernet(Key)
    return cipher
cipher=GenerateKey(UsernameAndPassword=os.urandom(128))

def Decrypt(Data):
    DecryptedData=cipher.decrypt(Data)
    return DecryptedData

def Encrypt(Data):
    Data=Data.encode()
    EncryptedData=cipher.encrypt(Data)
    return EncryptedData

Steve=Encrypt(Data="I LOVE IT WHEN PEOPLE DONT UNDERSTAND WHAT IM SAYING")#Has to be multiple of 128 for AES encryption to work will find a solution to this later
print(Steve)
print(Decrypt(Steve))
