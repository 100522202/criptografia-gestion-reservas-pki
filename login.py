import json
import os
import hash_functions
import key_management

USUARIOS_FILE = "database/usuarios.json"

def cargar_usuarios():
    if not os.path.exists(USUARIOS_FILE):
        return {}
    with open(USUARIOS_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def login_usuario(usuario_name:str, password):
    """Método que guarda un usuario. Recibe su usuario y su contraseña para
    comprobar que existe y si existe, compara la contraseña recibida con la 
    almacenada (que está hasheada)."""
    usuarios = cargar_usuarios()

    if usuario_name not in usuarios:
        return False, "Usuario no existe"
    
    hash_guardado = usuarios[usuario_name]["password_hash"]

    if not hash_functions.verify_hash(password, hash_guardado):
        return False, "Contraseña incorrecta"
    
    rol = usuarios[usuario_name]["rol"]
    return True, f"Bienvenido, {usuario_name}. Rol: {rol}"