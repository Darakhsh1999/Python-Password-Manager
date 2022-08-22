from cryptography.fernet import Fernet
import sys

class Encrypter():

    '''Takes in byte key argument and decrypts from default path.
        If decrypted list is provided, then wont load from default
        path'''


    def __init__(self, key, *args):
        
        self.key = key
        self.encrypter = Fernet(self.key)

        self.encrypted_path = r"C:\Users\arash\Documents\python projects\AdvancedEncrypter\EncryptedPasswords.txt" # Encrypted text

        if len(args) == 0:
            self.decrypted_path = r"C:\Users\arash\Documents\python projects\AdvancedEncrypter\DecryptedPasswords.txt" # Decrypted text
            
            # Read in decrypted text
            with open(self.decrypted_path, "r") as text:
                self.decrypted_string = text.read()

            self.decrypted_list = self.decrypted_string.splitlines() # string list

        elif len(args) == 1:
            self.decrypted_list = list(args[0])
        else:
            raise ValueError("Too many optional arguments, expected 1 got ",str(len(args)))

        
        self.encrypted_list = [] # binary list

        # Encrypt file
        for word in self.decrypted_list:
            if word != "":
                self.encrypted_list.append(self.encrypter.encrypt(bytes(word,'utf-8')))
            else:
                self.encrypted_list.append(b'')

        self.encrypted_string = b'\n'.join(self.encrypted_list) # binary string
        
        # Write encrypted text
        with open(self.encrypted_path,'wb') as text:
            text.write(self.encrypted_string)


if __name__ == "__main__":
    
    if len(sys.argv) == 2:
        key = sys.argv[1].encode('utf-8') # str -> byte
        print("Key used to encrypt", key)
        obj = Encrypter(key)
    else:
        raise ValueError(f"Script only takes in one argument but were given {len(sys.argv)-1}")