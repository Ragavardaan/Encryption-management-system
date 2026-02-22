from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
import base64

import mysql.connector

conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",  # default for XAMPP
    database="encryption_db"
)
cursor = conn.cursor()

def pad(text, block_size):
    pad_len = block_size - len(text) % block_size
    return text + chr(pad_len) * pad_len

def unpad(text):
    return text[:-ord(text[-1])]

def generate_key(algo):
    return get_random_bytes(16 if algo == 'AES' else 8)

def encrypt(plaintext, algo):
    key = generate_key(algo)
    cipher = AES.new(key, AES.MODE_ECB) if algo == 'AES' else DES.new(key, DES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(plaintext, cipher.block_size).encode())
    # Return both ciphertext and key as base64 strings
    return base64.b64encode(ct_bytes).decode(), base64.b64encode(key).decode()

def decrypt(ciphertext, key, algo):
    key_bytes = base64.b64decode(key)
    ct_bytes = base64.b64decode(ciphertext)
    cipher = AES.new(key_bytes, AES.MODE_ECB) if algo == 'AES' else DES.new(key_bytes, DES.MODE_ECB)
    return unpad(cipher.decrypt(ct_bytes).decode())