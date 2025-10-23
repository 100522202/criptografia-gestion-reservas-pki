import os
import json
from base64 import b64encode
from base64 import b64decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

class Booking:
    def __init__(self, usuario_asociado, datos):
        self.datos = datos
        self.usuario_asociado = usuario_asociado

    def cifrar_reserva(self) -> dict:
        """Método que va a cifrar la reserva de manera híbrida.
        Cifrará la reserva con AES (clave aleatoria) y cifrara esa clave
        con la clave pública del usuario. Devuelve la reserva cifrada y los 
        elementos necesarios para descifrarla en un diccionario: 
        reserva cifrada, clave aes, nonce"""

        # Codificamos los datos como bytes para que AES pueda usarlos
        datos_byte = self.datos.encode()
        usuario_bytes = self.usuario_asociado.encode()

        #Generamos la clave AES aleatoria
        aes_clave = AESGCM.generate_key(bit_length=256) #32 bytes

        #Creamos un objeto AESGCM con la clave anterior
        aesgcm = AESGCM(aes_clave)

        #Generamos un nonce de 12 bytes (semilla única para cada cifrado)
        nonce = os.urandom(12)

        #Ciframos los datos de la reserva con AES-GCM: solo será válida para el usuario asociado
        reserva_cifrada = aesgcm.encrypt(nonce, datos_byte, associated_data=usuario_bytes)

        #Ahora debemos cifrar esta clave AES con la clave pública

        #Cargamos la clave pública desde su archivo.pem
        ruta_clave_publica = "claves/" + self.usuario_asociado + "_public.pem"
        with open(ruta_clave_publica, "rb") as f:
            # Convertimos a objeto de clave pública
            clave_publica = serialization.load_pem_public_key(f.read())

        # Ciframos la clave AES con la clave pública (RSA) del usuario
        aes_clave_cifrada = clave_publica.encrypt(aes_clave,padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), 
            algorithm=hashes.SHA256(),label=None))
        

        #Devolvemos un tupla con los datos cifrados y lo que necesitamos para desencriptarlos:
        #Tenemos que guardar el nonce, los datos, la clave cifrada
        return {"reserva_cifrada":reserva_cifrada, 
                "aes_clave_cifrada": aes_clave_cifrada, "nonce": nonce}



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
    
def almacenar_reserva(reserva_cifrada:dict, ruta_archivo:str) -> bool:
    """Método que almacena una reserva cifrada en una ruta especificada
    que en nuestro caso debe ser reservas.json. Devuelve True si se almacena
    correctamente, False eoc."""
    # Validar que la reserva esté cifrada
    if not is_encrypted(reserva_cifrada):
         return False
    
    # Convertir los datos a b64 para poder almacenarlos en el json
    datos_a_guardar = {
        "reserva_cifrada": bytes_a_base64(reserva_cifrada["reserva_cifrada"]),
        "aes_clave_cifrada": bytes_a_base64(reserva_cifrada["aes_clave_cifrada"]),
        "nonce": bytes_a_base64(reserva_cifrada["nonce"])
    }

    # Si el archivo existe, leemos el contenido para añadir la nueva reserva
    if os.path.exists(ruta_archivo):
        with open(ruta_archivo, "r") as f:
            try:
                todas_las_reservas = json.load(f)
            except json.JSONDecodeError:
                todas_las_reservas = []
    else:
        todas_las_reservas = []
    # Añadir
    todas_las_reservas.append(datos_a_guardar)
    # Guardar de nuevo
    with open(ruta_archivo, "w") as f:
        json.dump(todas_las_reservas, f, indent=4)

    return True

def is_encrypted(reserva: dict):
     """Devuelve True si una reserva está cifrada, False eoc."""
     if not isinstance(reserva, dict):
          return False
     if not("reserva_cifrada" in reserva and "aes_clave_cifrada" in reserva and "nonce" in reserva):
          return False
     return True

def bytes_a_base64(data: bytes) -> str:
    """Convierte bytes a string en Base64."""
    return b64encode(data).decode()
          