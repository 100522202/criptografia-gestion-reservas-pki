""" Funciones relacionadas con el registro de usuario"""
import json
import os
import password_management
from key_management import generar_par_claves 

USUARIOS_FILE = "database/usuarios.json"
# TODO: CIFRAR USUARIOS ANTES DE GUARDARLOS, DESCIFRAR SI QUEREMOS OBTENER SU INFO
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

def registro_usuario(usuario_name, password, nombre, apellidos, correo):
    hash_psw = password_management.hash_password(password)

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

    generar_par_claves(usuario_name, password)
    guardar_usuarios(usuarios)
    return True, "Usuario registrado correctamente."
