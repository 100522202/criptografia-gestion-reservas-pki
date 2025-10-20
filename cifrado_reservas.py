import os
import json
from base64 import b64encode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def cifrar_reserva(usuario_name:str, datos_reserva:dict) -> dict:
    """Método que va a cifrar la reserva de manera híbrida.
    Cifrará la reserva con AES (clave aleatoria) y cifrara esa clave
    con la clave pública del usuario"""

    #Primero convertimos los datos a JSON y los codificamos como bytes para que 
    #AES pueda usarlos
    reserva_json = json.dump(datos_reserva).encode()

    #Generamos la clave AES aleatoria
    aes_clave = AESGCM.generate_key(bit_length=256) #32 bytes

    #Creamos un objeto AESGCM con la clave anterior
    aesgcm = AESGCM(aes_clave)

    #Generamos un nonce de 12 bytes (semilla única para cada cifrado)
    nonce = os.urandom(12)

    #Ciframos los daros de la reserva con AES-GCM
    #Esto devolverá la reserva cifrada y un tag de autenticación
    texto_cifrado = aesgcm.encrypt(nonce, reserva_json, associated_data=None)

    #Ahora debemos cifrar esta clave AES con la clave pública

    #Cargamos la clave pública desde su archivo.pem
    ruta_clave_publica = f"claves/{usuario_name}_public.pem"
    with open(ruta_clave_publica, "rb") as f:
        clave_publica = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

    clave_aes_cifrada = clave_publica.encrypt(
        aes_clave,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Máscara generada con SHA256
            algorithm=hashes.SHA256(),                   # Algoritmo principal
            label=None
     )
    )
    

    #Devolvemos un diccionario con los datos cifrados en base64
    #Tenemos que guardar el nonce, los datos, la clave cifrada
    return {
        "usuario": usuario_name,
        "nonce": b64encode(nonce).decode(),                 # El nonce usado para el cifrado AES
        "texto_cifrado": b64encode(texto_cifrado).decode(),       # Los datos cifrados
        "clave_cifrada": b64encode(clave_aes_cifrada).decode()  # La clave AES cifrada con RSA
    }