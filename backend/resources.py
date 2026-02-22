import mysql.connector

conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",  
    database="encryption_db"
)
cursor = conn.cursor()

def get_resources():
    return {
        "AES": "Symmetric key algorithm. Fast and secure for large data.",
        "DES": "Older symmetric key algorithm. Less secure now.",
        "RSA": "Asymmetric algorithm using public/private keys.",
        "Diffie-Hellman": "Key exchange method to securely share secret keys."
    }