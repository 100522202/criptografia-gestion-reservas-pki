import json
import os
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidKey

USUARIOS_FILE = "usuarios.json"

def cargar_usuarios():
    if not os.path.exists(USUARIOS_FILE):
        return {}
    with open(USUARIOS_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}
        

def verify_password(password: str, encoded: str) -> bool:
    try:
        Argon2id.verify_phc_encoded(encoded.encode(), password.encode())
        return True
    except InvalidKey:
        return False

def login_usuario(usuario_name:str, password:str):
    usuarios = cargar_usuarios()

    if usuario_name not in usuarios:
        return False, "Usuario no existe"
    
    hash_guardado = usuarios[usuario_name]["password_hash"]

    if not verify_password(password, hash_guardado):
        return False, "Contraseña incorrecta"
    
    rol = usuarios[usuario_name]["rol"]
    return True, f"Bienvenido, {usuario_name}. Rol: {rol}"