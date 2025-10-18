import json
import os
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidKey
import os, base64
from generar_claves import cargar_clave_privada

USUARIOS_FILE = "usuarios.json"

def cargar_usuarios():
    if not os.path.exists(USUARIOS_FILE):
        return {}
    with open(USUARIOS_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}
        

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=2,
        lanes=1,
        memory_cost=32 * 1024,
        ad=None,
        secret=None
    )
    return kdf.derive_phc_encoded(password.encode())

def verify_password(password: str, encoded: str) -> bool:
    try:
        data = base64.b64decode(encoded.encode("utf-8"))
        salt = data[:16]
        stored_key = data[16:]

        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=2,
            lanes=1,
            memory_cost=32 * 1024,
            ad=None,
            secret=None
        )

        # Esta línea lanza InvalidKey si la verificación falla
        kdf.verify(password.encode(), stored_key)
        return True
    except InvalidKey:
        return False



def login_usuario(usuario_name:str, password):
    usuarios = cargar_usuarios()

    if usuario_name not in usuarios:
        return False, "Usuario no existe"
    
    hash_guardado = usuarios[usuario_name]["password_hash"]

    if not verify_password(password, hash_guardado):
        return False, "Contraseña incorrecta"
    
    #Cargamos la clave privada del usuario
    clave_privada = cargar_clave_privada(usuario_name, password)
    rol = usuarios[usuario_name]["rol"]
    return True, f"Bienvenido, {usuario_name}. Rol: {rol}"