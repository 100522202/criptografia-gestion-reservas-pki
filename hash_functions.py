import os
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidKey

def hash_text(password: str) -> str:
    """
    Genera un hash seguro de un texto usando Argon2id.

    Se utiliza Argon2id como función de derivación de claves, incluyendo una sal aleatoria
    de 16 bytes para proteger contra ataques de diccionario y rainbow tables.
    El resultado combina la sal y la clave derivada, codificados en base64.

    Args:
        text (str): texto plano que se desea hashear.

    Returns:
        str: Cadena en base64 que contiene la sal concatenada con el hash derivado.
    """
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

    key = kdf.derive(password.encode())

    # Guardamos sal + clave derivada en base64
    encoded = base64.b64encode(salt + key).decode("utf-8")
    print(
        f"[DEBUG] hash_functions: Argon2id hash generado (memoria=32MB, iteraciones=2, salida={len(key)} bytes, salt={len(salt)} bytes)."
    )
    return encoded

def verify_hash(text: str, encoded: str) -> bool:
    """
    Verifica si una texto coincide con un hash previamente generado.

    Decodifica la cadena base64, separa la sal y la clave derivada, y vuelve a aplicar 
    Argon2id con los mismos parámetros para comprobar si el texto proporcionado 
    genera la misma clave. Si la verificación falla, se captura la excepción InvalidKey.

    Args:
        text (str): Texto plano a verificar.
        encoded (str): Hash almacenado en formato base64 (sal + hash).

    Returns:
        bool: True si la contraseña es correcta, False si no coincide.
    """
    salt = b""
    stored_key = b""
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
        kdf.verify(text.encode(), stored_key)
        print(
            f"[DEBUG] hash_functions: Argon2id verificación correcta (memoria=32MB, iteraciones=2, salida={len(stored_key)} bytes, salt={len(salt)} bytes)."
        )
        return True
    except InvalidKey:
        print("[WARNING] hash_functions: Verificación Argon2id fallida (entrada no coincide).")
        return False


def stable_hash(text: str) -> str:
    """
    Genera un identificador determinista basado en SHA-256 del texto dado.

    Se emplea para etiquetar datos de manera consistente sin exponer el texto original.
    """
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    print("[DEBUG] hash_functions: SHA-256 estable generado (salida=256 bits).")
    return base64.b64encode(digest).decode("utf-8")
