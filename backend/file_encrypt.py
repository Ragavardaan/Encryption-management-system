# ...existing code...
from cryptography.fernet import Fernet

def encrypt_content(content_bytes: bytes):
    """
    Encrypt bytes content and return (ciphertext_bytes, key_bytes)
    """
    key = Fernet.generate_key()           # bytes
    fernet = Fernet(key)
    ciphertext = fernet.encrypt(content_bytes)
    return ciphertext, key

def decrypt_content(ciphertext_bytes: bytes, key_str: str):
    """
    Decrypt bytes content using key (string or bytes). Returns plaintext bytes.
    key_str may be bytes or str; if str it will be encoded to utf-8.
    """
    if isinstance(key_str, bytes):
        key_bytes = key_str
    else:
        key_bytes = key_str.encode()
    fernet = Fernet(key_bytes)
    plaintext = fernet.decrypt(ciphertext_bytes)
    return plaintext
# ...existing code...