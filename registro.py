import json
import os
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

def guardar_usuarios(usuarios):
    with open(USUARIOS_FILE, "w", encoding="utf-8") as f:
        json.dump(usuarios, f, indent=2)

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
        Argon2id.verify_phc_encoded(encoded, password.encode())
        return True
    except InvalidKey:
        return False

def registro_usuario(usuario_name, password, nombre, apellidos, correo, archivo=USUARIOS_FILE):
    hash_psw = hash_password(password)

    usuarios = cargar_usuarios()

    if usuario_name in usuarios:
        return False, "El usuario ya existe"

    usuarios[usuario_name] = {
        "rol": "usuario_comun",
        "usuario_name": usuario_name,
        "password_hash": hash_psw,
        "nombre": nombre,
        "apellidos": apellidos,
        "correo_electronico": correo
    }

    guardar_usuarios(usuarios)
    return True, "Usuario registrado correctamente."
