import os
from certificate_management import cargar_certificado
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.hazmat.backends import default_backend

CARPETA_CLAVES = "claves"

def generar_clave_privada(password:str):
    """Función que genera una clave privada RSA, la serializa y la cifra con 
    la contraseña del usuario. Va a devovler los bytes serializados de la clave privada y la clave"""

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

    # ES UNA FUNCIÓN OBSOLETA QUE SE UTILIZABA EN LA VERSION DEL PRIMER ENTREGABLE

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

    # YA NO GENERAMOS CLAVE PÚBLICA
    # public_pem = generar_clave_publica(clave_privada)

    #Las guardamos en archivos .pem
    ruta_privada = os.path.join(CARPETA_CLAVES, f"{usuario_name}_private.pem")
    # ruta_publica = os.path.join(CARPETA_CLAVES, f"{usuario_name}_public.pem")
    
    with open(ruta_privada, "wb") as f:
        f.write(pem_privado)

    # with open(ruta_publica, "wb") as f:
        # f.write(public_pem)
    
    return {
        "mensaje":"Claves guardadas correctamente",
        # "clave_publica_path": ruta_publica,
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

def validar_clave_publica(clave_pub, clave_pub_cert):
    """Funcion que valida que la clave publica recibida coincide con la 
    clave publica del certificado del usuario"""
    return clave_pub == clave_pub_cert

def cargar_clave_publica(usuario_name: str):
    """
    Carga la clave pública RSA del usuario desde su archivo .pem.
    Retorna el objeto clave pública si tiene éxito, o lanza una excepción si falla.
    """
    # MODIFICACION PARA PRUEBAS
    #certificado_usuario = cargar_certificado("rida")

    certificado_usuario = cargar_certificado(usuario_name)
    
    # Vamos a verificar la firma con el certificado de la AC1

    # Lo cargamos
    with open("AC1/ac1cert.pem", "rb") as f:
        cert_ac_bytes = f.read()

    certificado_ac = x509.load_pem_x509_certificate(
        cert_ac_bytes, 
        default_backend()
    )

    # Verificamos
    try:
        certificado_usuario.verify_directly_issued_by(certificado_ac)
    except Exception as e:
        print("Error verificando el certificado:", e)
        raise
    
    print("[DEBUG] El certificado ha sido verificado correctamente")


    return certificado_usuario.public_key()

def rsa_oaep_encrypt(clave_publica, datos: bytes) -> bytes:
    """Cifra datos con RSA-OAEP usando SHA-256."""
    ciphertext = clave_publica.encrypt(
        datos,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def rsa_oaep_decrypt(clave_privada, datos_cifrados: bytes) -> bytes:
    """Descifra datos con RSA-OAEP usando SHA-256."""
    plaintext = clave_privada.decrypt(
        datos_cifrados,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext
