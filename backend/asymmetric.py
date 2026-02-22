from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

key = RSA.generate(2048)
private_key = key.export_key().decode()
public_key = key.publickey().export_key().decode()

def get_keys():
    return private_key, public_key  # Return the generated keys

def rsa_encrypt(message, pub_key):
    """
    Encrypt a plaintext message with the given public key
    """
    rsa_key = RSA.import_key(pub_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted).decode()

def rsa_decrypt(cipher_text,private_key):
    """
    Decrypt a base64-encoded cipher text using the private key
    """
    cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    decrypted = cipher.decrypt(base64.b64decode(cipher_text)).decode()
    return decrypted
