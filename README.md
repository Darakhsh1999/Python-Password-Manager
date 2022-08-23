# Python-Password-Manager

## Minimalistic password manager with simple GUI using fernet symmetric 32-byte encryption.

**Quick Setup**

1. Create a `DecryptedPasswords.txt` file with your app, user and password information following the format given in [TemplatePasswords.txt](https://github.com/Darakhsh1999/Python-Password-Manager/blob/main/TemplatePasswords.txt) (don't edit first row)
2. In `GenerateKey.py` enter in your master password in the ***password_string*** variable (clear after use)
3. Run `GenerateKey.py` and copy your generated 32-byte key
4. In `Encrypter.py` replace  ***d_path*** with the path to `DecryptedPasswords.txt` and replace ***e_path*** to where you want the encrypted information to be stored
5. Run `Encrypter.py` from command line and pass in your generated key as the single argument
6. Remove the `DecryptedPasswords.txt` file from your PC
7. In `Decrypter.py` replace ***e_path*** to the same path given in `Encrypter.py`
8. Now you can run `Decrypter.py` and you'll be prompted with a window to enter your master password 

---

**Requirements**

- python 3.9.12
- cryptography 3.4.8 
