# TODO: verificar que esto está bien
import os
import base64
from argon2.low_level import hash_secret_raw, Type

def generar_token_sesion(password: str, salt: bytes = None) -> str:
    if salt is None:
        salt = os.urandom(16)
    key = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=2,
        memory_cost=32*1024,
        parallelism=1,
        hash_len=32,
        type=Type.ID
    )
    token = base64.b64encode(salt + key).decode("utf-8")
    return token
