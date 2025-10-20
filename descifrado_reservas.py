import json
from base64 import b64decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def descifrar_reserva(usuario_name:str, password:str, reserva_cifrada:dict) ->dict:
    """Método que descifra la reserva cifrada con AES-GCM y RSA
    Recupera la clave privada del usuario luego usa esa clave pare descifrar
    la clave AES. Y con esa clave AES descifra el contenido de la reserva"""

    #Primero debemos cargar la clave priamria del usuario desde su archivo .pem
    #Usando su contaseña
    ruta_clave_privada = f"claves/{usuario_name}_private.pem"
    with open(ruta_clave_privada, "rb") as f:
        clave_privada = serialization.load_pem_private_key(
            f.read(),
            password=password.encode(),  # Necesitamos la contraseña original
            backend=default_backend()
        )

    #Desciframos la clave AES que está cifrada con la clave pública RSA
    clave_aes = clave_privada.decrypt(
        b64decode(reserva_cifrada["clave_cifrada"]), #Convertimos de base64 a bytes
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    #Creamoso el objeto AES-GCM con la clave AES recuperada
    aesgcm = AESGCM(clave_aes)

    #Obtenemos el nonce y el mensaje cifrado (en base64) y los convertimos a bytes
    nonce = b64decode(reserva_cifrada["nonce"])
    texto_cifrado = b64decode(reserva_cifrada["texto_cifrado"])

    #Desciframos el mensaje
    datos_descifrados = aesgcm.decrypt(nonce, texto_cifrado, associated_data=None)

    #Convertir los bytes descifrados a texto y luego a diccionario
    return json.loads(datos_descifrados.decode())