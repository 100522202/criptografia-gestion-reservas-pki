import os
import base64
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidKey

def hash_text(password: str) -> str:
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
    return base64.b64encode(salt + key).decode("utf-8")

def verify_hash(password: str, encoded: str) -> bool:
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