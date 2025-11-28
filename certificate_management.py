from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
import datetime


# Rutas de la AC
RUTA_CERTIFICADO_CA = "AC1/ac1cert.pem"
RUTA_CLAVE_PRIVADA_CA = "AC1/privado/ca1key.pem"

def generar_csr_usuario(usuario_name, nombre, apellidos, correo, clave_privada_usuario) -> bytes:
    """
    Genera una Solicitud de Firma de Certificado (CSR) utilizando la clave privada
    y los datos del usuario, siguiendo el patrón de cryptography.
    
    Devuelve la CSR codificada en formato PEM.
    """
    if clave_privada_usuario is None:
        return None

    # Quienes somos
    subject = x509.Name([
        # Información extra que aparecía en el ejemplo de cryptography para un certificado de usuario
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Leganes"),
        # El Common Name (CN) es el identificador principal
        x509.NameAttribute(NameOID.COMMON_NAME, usuario_name), 
        # Incluimos información adicional del usuario
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, correo),
        x509.NameAttribute(NameOID.SURNAME, apellidos),
        x509.NameAttribute(NameOID.GIVEN_NAME, nombre),
    ])

    # Construir el objeto CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        subject
    ).sign(
        clave_privada_usuario,
        hashes.SHA256() # Algoritmo de hash recomendado para la firma del CSR
    )

    # Codificar la CSR a formato PEM para luego guardarla
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    print("[DEBUG] Solicitud CSR creada correctamente usando el estándar X509 y el algoritmo SHA-256")
    return csr_pem


def guardar_csr(usuario_name, csr_pem):
    """Escribe el CSR a un archivo .csr en la carpeta certs/"""
    if not os.path.exists("certs"):
        os.makedirs("certs")
    
    # Escribir la CSR al disco para dársela a la CA (o al proceso de firma)
    with open(f"solicitud_certs/{usuario_name}.csr", "wb") as f:
        f.write(csr_pem)
    print(f"[DEBUG] CSR guardado en certs/{usuario_name}.csr")