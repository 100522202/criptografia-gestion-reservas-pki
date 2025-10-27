import os
import json
import hash_functions
import key_management
from base64 import b64encode
from base64 import b64decode
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

RESERVAS_FILE = "database/reservas.json"

class Booking:
    def __init__(self, usuario_asociado: str, datos:str, fecha_asociada:str):
        self.datos = datos
        self.usuario_asociado = usuario_asociado
        self.fecha_asociada = fecha_asociada

    def cifrar_reserva(self) -> dict:
        """Método que va a cifrar la reserva de manera híbrida.
        Cifrará la reserva con AES (clave aleatoria) y cifrara esa clave
        con la clave pública del usuario. Devuelve la reserva cifrada y los 
        elementos necesarios para descifrarla en un diccionario: 
        reserva cifrada, clave aes, nonce"""
        # Construimos la lista de datos
        datos_completos = [self.usuario_asociado, self.fecha_asociada, self.datos]  

        # Además, guardaremos el usuario hasheado para que luego sea más fácil buscar sus reservas
        usuario_hasheado = hash_functions.hash_text(self.usuario_asociado)

        # Codificamos los datos como bytes para que AES pueda usarlos
        datos_byte = json.dumps(datos_completos).encode()
        usuario_bytes = self.usuario_asociado.encode()

        #Generamos la clave AES aleatoria
        aes_clave = AESGCM.generate_key(bit_length=256) #32 bytes

        #Creamos un objeto AESGCM con la clave anterior
        aesgcm = AESGCM(aes_clave)

        #Generamos un nonce de 12 bytes (semilla única para cada cifrado)
        nonce = os.urandom(12)

        #Ciframos los datos de la reserva con AES-GCM: solo será válida para el usuario asociado: AUTENTICACIÓN
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
        
        # Cargamos también la clave pública del administrador
        ruta_clave_publica_admin = "claves/admin_public.pem"
        with open(ruta_clave_publica_admin, "rb") as f:
            clave_publica_admin = serialization.load_pem_public_key(f.read())

        # Ciframos la misma clave AES con la clave pública del administrador
        aes_clave_cifrada_admin = clave_publica_admin.encrypt(
            aes_clave,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Ciframos también el nombre del usuario con la clave pública del admin para mantener la privacidad
        usuario_cifrado_admin = clave_publica_admin.encrypt(
            self.usuario_asociado.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        #Devolvemos un tupla con los datos cifrados y lo que necesitamos para desencriptarlos:
        #Tenemos que guardar el nonce, los datos, la clave cifrada
        return {"usuario_hasheado": usuario_hasheado,"reserva_cifrada":reserva_cifrada, 
                "aes_clave_cifrada": aes_clave_cifrada, "aes_clave_cifrada_admin": aes_clave_cifrada_admin, 
                "nonce": nonce, "usuario_original_cifrado": usuario_cifrado_admin}



def descifrar_reserva(reserva: dict, usuario_name: str, password: str) -> dict:
    """
    Descifra una reserva cifrada con el esquema híbrido AES-GCM + RSA. Para ello,
    carga la clave privada del usuario, descifra el AES, descifra el contenido
    usando AES-GCM con la clave AES y el nonce. Devuelve los datos de la reserva
    como diccionario.

    Flujo:
    1. Carga la clave privada del usuario (protegida por contraseña).
    2. Descifra la clave AES con la clave privada RSA.
    3. Descifra el contenido de la reserva usando AES-GCM con la clave AES y el nonce.
    4. Devuelve los datos originales de la reserva como diccionario o lista.

    Parámetros:
    - reserva (dict): Diccionario con las claves:
        - "reserva_cifrada": str (Base64 del ciphertext AES-GCM)
        - "aes_clave_cifrada": str (Base64 de la clave AES cifrada con RSA)
        - "nonce": str (Base64 del nonce de AES-GCM)
    - usuario_name (str): Nombre de usuario asociado a la reserva.
    - password (str): Contraseña del usuario para desbloquear su clave privada.
    """

    # Cargar la clave privada del usuario
    ruta_clave_privada = f"claves/{usuario_name}_private.pem"
    with open(ruta_clave_privada, "rb") as f:
        clave_privada = serialization.load_pem_private_key(
            f.read(),
            password=password.encode(),
            backend=default_backend()
        )

    # Seleccionamos qué clave cifrada usar dependiendo del usuario:
    # si el usuario es "admin", usamos la clave AES cifrada con la pública del admin,
    # en caso contrario, usamos la clave cifrada con la pública del usuario.
    if usuario_name == "admin" and "aes_clave_cifrada_admin" in reserva:
        aes_clave_cifrada_bytes = b64decode(reserva["aes_clave_cifrada_admin"])
    else:
        aes_clave_cifrada_bytes = b64decode(reserva["aes_clave_cifrada"])

    # Descifrar la clave AES 
    clave_aes = clave_privada.decrypt(
        aes_clave_cifrada_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Descifrar la reserva con AES-GCM 
    aesgcm = AESGCM(clave_aes)
    nonce = b64decode(reserva["nonce"])
    reserva_cifrada_bytes = b64decode(reserva["reserva_cifrada"])
    if usuario_name == "admin":
        usuario_cifrado_b64 = reserva.get("usuario_original_cifrado")
        if not usuario_cifrado_b64:
            raise ValueError("Reserva sin información de titular para descifrado por admin.")

        usuario_cifrado = b64decode(usuario_cifrado_b64)
        usuario_asociado_bytes = clave_privada.decrypt(
            usuario_cifrado,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        usuario_asociado = usuario_asociado_bytes.decode()
    else:
        usuario_asociado = usuario_name

    usuario_bytes = usuario_asociado.encode()

    datos_descifrados_bytes = aesgcm.decrypt(
        nonce,
        reserva_cifrada_bytes,
        associated_data=usuario_bytes
    )

    # Convertir bytes a datos originales
    datos_descifrados = json.loads(datos_descifrados_bytes.decode("utf-8"))
    return datos_descifrados

    
def almacenar_reserva(reserva_cifrada:dict, ruta_archivo:str) -> bool:
    """Método que almacena una reserva cifrada en una ruta especificada
    que en nuestro caso debe ser reservas.json. Devuelve True si se almacena
    correctamente, False eoc."""
    # Validar que la reserva esté cifrada
    if not is_encrypted(reserva_cifrada):
         return False
    
    # Convertir los datos a b64 para poder almacenarlos en el json
    datos_a_guardar = {
        "usuario_hasheado": reserva_cifrada["usuario_hasheado"],
        "reserva_cifrada": bytes_a_base64(reserva_cifrada["reserva_cifrada"]),
        "aes_clave_cifrada": bytes_a_base64(reserva_cifrada["aes_clave_cifrada"]),
        "aes_clave_cifrada_admin": bytes_a_base64(reserva_cifrada["aes_clave_cifrada_admin"]),
        "nonce": bytes_a_base64(reserva_cifrada["nonce"]),
        "usuario_original_cifrado": bytes_a_base64(reserva_cifrada["usuario_original_cifrado"])
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


def obtener_reservas(usuario_asociado:str, password:str) -> list:
    """Método que saca todas las reservas de un usuario de reservas.json"""
    if not os.path.exists(RESERVAS_FILE):
        return []

    with open(RESERVAS_FILE, "r") as f:
        try:
            todas_las_reservas = json.load(f)
        except json.JSONDecodeError:
            return []

    # Si el usuario es admin, obtiene todas las reservas
    if usuario_asociado == "admin":
        return obtener_todas_reservas("admin", password)

    reservas_usuario = []
    for reserva in todas_las_reservas:
        try:
            usuario_hasheado_guardado = reserva.get("usuario_hasheado")
            if not usuario_hasheado_guardado:
                continue
            if not hash_functions.verify_hash(usuario_asociado, usuario_hasheado_guardado):
                continue
            datos = descifrar_reserva(reserva, usuario_asociado, password)
            reservas_usuario.append(datos)
        except Exception:
            continue

    return reservas_usuario


def obtener_todas_reservas(usuario_admin: str, password_admin: str) -> list:
    """Devuelve todas las reservas descifradas usando la clave del admin."""
    if usuario_admin != "admin":
        return []

    if not os.path.exists(RESERVAS_FILE):
        return []

    with open(RESERVAS_FILE, "r") as f:
        try:
            todas_las_reservas = json.load(f)
        except json.JSONDecodeError:
            return []

    resultado = []
    for reserva in todas_las_reservas:
        try:
            datos = descifrar_reserva(reserva, "admin", password_admin)
            resultado.append(datos)
        except Exception:
            continue

    return resultado


def is_encrypted(reserva: dict):
     """Devuelve True si una reserva está cifrada, False eoc."""
     if not isinstance(reserva, dict):
          return False
     required_keys = {
         "reserva_cifrada",
         "aes_clave_cifrada",
         "aes_clave_cifrada_admin",
         "nonce",
         "usuario_original_cifrado"
     }
     if not required_keys.issubset(reserva):
          return False
     return True


def bytes_a_base64(data: bytes) -> str:
    """Convierte bytes a string en Base64."""
    return b64encode(data).decode()


def guardar_reserva(usuario, email, telefono, dni, fecha, ventana_crear):
    """Guarda una nueva reserva cifrada en el archivo JSON."""
    if not all([email, telefono, dni, fecha]):
        messagebox.showwarning("Campos vacíos", "Debes completar todos los campos obligatorios.")
        return

    try:
        # Construimos un diccionario con los datos de la reserva
        datos = {
            "email": email,
            "telefono": telefono,
            "dni": dni
        }

        # Creamos y ciframos la reserva
        booking = Booking(usuario, json.dumps(datos), fecha)
        reserva_cifrada = booking.cifrar_reserva()

        # Guardamos en el archivo JSON
        almacenar_reserva(reserva_cifrada, RESERVAS_FILE)

        messagebox.showinfo("Éxito", "Reserva creada y cifrada correctamente.")
        ventana_crear.destroy()
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo crear la reserva:\n{e}")
