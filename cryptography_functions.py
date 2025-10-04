from cryptography.fernet import Fernet

def generate_key():
    """Función que genera una clave segura"""
    pass

def encrypt_message(message: str, key: bytes) -> bytes:
    """Función que cifra datos antes de guardarlos en JSON"""
    pass

def decrypt_massage(token: bytes, key:bytes) -> str:
    """Función que permite descifrar los datos por si los necesitamos"""
    pass

def hash_password(password: str) -> str:
    """Función que genera un hash seguro de la contraseña"""
    pass