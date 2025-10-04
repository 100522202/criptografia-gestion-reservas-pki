import cryptography_functions
import json

"""Funciones para gestionar el archivo json de base de datos"""

# TODO: FALTA TODA LA LÓGICA DE CIFRADO/DESCIFRADO EN TODAS LAS FUNCIONES

def load_users() -> dict:
    """Función que devuelve el diccionario con TODOS los usuarios de la base de datos (json). Devuelve un diccionario vacío en caso de error."""
    try:
        with open("database.json", "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print("Error: archivo no encontrado")
        return {}
    except json.JSONDecodeError:
        print("Error: JSONDecodeError")
        return {}
        

def save_users(users) -> None:
    """Función que almacena el diccionario users en la base de datos json"""
    if not isinstance(users, dict):
        raise TypeError("users debe ser un diccionario")
    # Con el modo "w", sobrescribimos el json cada vez con el dict users, no añadimos ningún usuario nuevo 
    with open("database.json", "w") as file:
        json.dump(users, file, indent = 4, sort_keys = True)


def register_user(username, password) -> bool:
    """Función que registra un usuario, para lo que: Comprueba si el usuario ya existe. Hashea la contraseña. Añade el usuario al diccionario y llama a save_users. Devuelve True si se registra correctamente, False eoc."""
    users = load_users()
    if username in users.keys():
        print("El usuario ya está registrado: no se puede dar de alta")
        return False
    

    # TODO: Falta hashear la contraseña con la función que implementemos/copiemos en crypto_functions.py
    hashed_password = ""

    # Añadimos usuario al diccionario y lo guardamos
    users[username] = {"password": hashed_password, "rol": "user", "reservas": []}

    save_users(users)
    print("Usuario registrado correctamente")
    return True
    

def authenticate_user(username, password) -> bool:
    """Función que verifica que el usuario que accede al sistema es quien dice ser. Se admitirá el acceso SI Y SOLO SI el username existe en el JSON y si la contraseña introducida coincide con la registrada. Devuelve True en caso de éxito, False eoc"""
    users = load_users()

    # TODO
    if (username in users.keys()): # and ...
        pass

def get_user(username) -> dict:
    """Función (OPCIONAL) que devuelve la información de un usuario"""
    users = load_users()

    if username in users.keys():
        return users[username]
    return {}