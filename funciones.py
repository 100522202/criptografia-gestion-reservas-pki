from cryptography.fernet import Fernet

import os
import json
from base64 import b64encode, b64decode
from cryptography.exceptions import InvalidKey
# Para el hasheo de contraseñas: Argon2
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

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

def hash_password(password: str):
    """Función que genera un hash seguro de la contraseña"""
    #generamos el salta para que no haya dos contraseñas iguales con el mismo hash
    salt = os.urandom(16)

    #Derivamos
    kdf = Argon2id(
        salt = salt,
        length=32,
        iterations=2,
        lanes=1,
        memory_cost=32 * 1024,
        ad=None,
        secret=None
    )

    return kdf.derive_phc_encoded(password.encode())



def verify_password(password: str) -> bool:
    """Función que comprueba si una contraseña introducida coincide con el hash guardado"""
    
    try:
        Argon2id.verify_phc_encoded(password.encode(), encoded)
        return True
    except InvalidKey:
        return False


def registro_usuario(usuario_name:str, password: str, nombre:str, apellidos: str, correo_electronico:str, archivo="usuarios.json"):
    """Función que va a registrar a nuestro usuario en la base de datos (json)"""
    hash_psw = hash_password(password)

    #Cargamos los usuarios existentes
    if os.path.exists(archivo):
        with open(archivo, "r") as f:
            usuarios = json.load(f)
    else:
        #Creamos la estructura vacía
        usuarios = {}

    if usuario_name in usuarios:
        return False, "El usuario ya existe"
    
    #Guardamos un nuevo usuario
    usuarios[usuario_name] = {
        "rol": "usuario_comun",
        "usuario_name": usuario_name,
        "password_hash": hash_psw,
        "nombre": nombre,
        "apellidos": apellidos,
        "correo_electronico": correo_electronico
    }
    
    #Escribirmos a nuestro nuevo usuario en la base de datos
    with open(archivo, "w") as f:
        json.dump(usuarios, f, indent=2)
    
    return True, "Usuario registrado correctamente."