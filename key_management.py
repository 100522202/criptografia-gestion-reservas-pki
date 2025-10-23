import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

CARPETA_CLAVES = "claves"

def generar_clave_privada(password:str):
    """FUncíon que genera una clave privada RSA, la serializa y la cifra con 
    la contraseña del usuario. Va a devovler los bytes serializados de la clave privada 
    y la clave"""

    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    pem_privado = clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )

    return pem_privado, clave_privada

def generar_clave_publica(clave_privada):
    """Esta función va va generar la clave pública a partir de su clave privada de cada usuario
    y devovlerá sus bytes serializados en PEM"""

    clave_publica = clave_privada.public_key()

    public_pem = clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return public_pem

def generar_par_claves(usuario_name:str, password:str):
    """Función que genera y guarda la clave pública y privada en
    archivos PEM. """

    #Tenemos que asegurarnos de que el archivo existe
    os.makedirs(CARPETA_CLAVES, exist_ok=True)

    #vamos a generar la clave privada y serializarla
    pem_privado, clave_privada = generar_clave_privada(password)

    #vamos a generar la clave pública a partir de la privada anterior
    public_pem = generar_clave_publica(clave_privada)

    #Las guardamos en archivos .pem
    ruta_privada = os.path.join(CARPETA_CLAVES, f"{usuario_name}_private.pem")
    ruta_publica = os.path.join(CARPETA_CLAVES, f"{usuario_name}_public.pem")
    
    with open(ruta_privada, "wb") as f:
        f.write(pem_privado)

    with open(ruta_publica, "wb") as f:
        f.write(public_pem)
    
    return {
        "mensaje":"Claves guardadas correctamente",
        "clave_publica_path": ruta_publica,
        "clave_privada_path": ruta_privada
    }

def cargar_clave_privada(usuario_name: str, password: str):
    """
    Carga la clave privada RSA del usuario cuando inicie sesion 
    desde su archivo .pem, descifrándola con su contraseña.
    Retorna el objeto clave privada si tiene éxito, o lanza una excepción si falla.
    """
    ruta_clave = f"claves/{usuario_name}_private.pem"
    
    with open(ruta_clave, "rb") as f:
        clave_privada = serialization.load_pem_private_key(
            f.read(),
            password=password.encode(),
            backend=default_backend()
        )

    return clave_privada
