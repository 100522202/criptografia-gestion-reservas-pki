from cryptography.fernet import Fernet
# Para el hasheo de contraseñas: Argon2
from cryptography.hazmat.primitives.kdf.argon2 import Argon2

import os

def generate_key() -> bytes:
    """Función que genera una clave segura. Devuelve la clave en bytes"""
    if os.path.exists("key.key"):
        with open("key.key", "rb") as key_file:
            key = key_file.read()
        return key
    # Si no existe, la generamos
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)
    return key

def encrypt_message(message: str, key: bytes) -> bytes:
    """Función que cifra datos antes de guardarlos en JSON. Devuelve los datos cifrados"""
    if not isinstance(message, str):
        raise TypeError("El mensaje a encriptar no es un string")
    
    msg_bytes = message.encode("utf-8")
    # Creamos el objeto Fernet
    f = Fernet(key)
    # La convertimos en bytes cifrados
    token = f.encrypt(msg_bytes)

    # Mensajes para transparencia del programa
    print("Algoritmo: Fernet (AES-128 con HMAC-SHA256)")
    print(f"Clave de {len(key)*8} bits utilizada") # Será de 256 bits
    print("Mensaje cifrado (base 64):", token.decode())


    return token


def decrypt_message(token: bytes, key:bytes) -> str:
    """Función que permite descifrar los datos. Devuelve los datos originales que pasamos a encrypt_message"""
    # Creamos el objeto fernet
    f = Fernet(key)

    # Desencriptamos el mensaje (y decodificamos)
    decrypted_bytes = f.decrypt(token)
    decrypted_message = decrypted_bytes.decode("utf-8")
    
    # Mensajes para transparencia del programa
    print("Algoritmo: Fernet (AES-128 con HMAC-SHA256)")
    print(f"Clave de {len(key)*8} bits utilizada") # Será de 256 bits
    print("Mensaje descifrado (base 64):", decrypted_message)

    return decrypted_message

def hash_password(password: str) -> str:
    """Función que genera un hash seguro de la contraseña"""
    pass

def verify_password(password: str, stored_hash:str) -> bool:
    """Función que comprueba si una contraseña introducida coincide con el hash guardado"""
    pass