import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

password_string = b"temp_password" # Make this your wanted password and keep safe

salt = b'2\xc5x\x9c\x02|\xc1|\x1d\xa4u?7\xcet\x13G\xa9\x8c\xfaAw\x97\x05\xdcP>\x81\x99>\xc7\x86'

kdf = PBKDF2HMAC(
    algorithm= hashes.SHA256(),
    length= 32,
    salt= salt,
    iterations= 500_000)

pw_key = base64.urlsafe_b64encode(kdf.derive(password_string))
print("Generated password key: ", pw_key)

