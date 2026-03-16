import mysql.connector

conn = mysql.connector.connect(
    host=os.environ.get("DB_HOST"),
    user=os.environ.get("DB_USER"),
    password=os.environ.get("DB_PASS"),
    database=os.environ.get("DB_NAME"),
    port=int(os.environ.get("DB_PORT", 3306))
)
cursor = conn.cursor()

def get_resources():
    return {
        "AES": "Symmetric key algorithm. Fast and secure for large data.",
        "DES": "Older symmetric key algorithm. Less secure now.",
        "RSA": "Asymmetric algorithm using public/private keys.",
        "Diffie-Hellman": "Key exchange method to securely share secret keys."
    }
