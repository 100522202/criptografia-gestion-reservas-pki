from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os


def generar_csr_usuario(usuario_name, nombre, apellidos, correo, clave_privada_usuario):
    """
    Genera una Solicitud de Firma de Certificado (CSR) utilizando la clave privada
    y los datos del usuario, siguiendo el patrón de cryptography.
    
    Returns:
        bytes: La CSR codificada en formato PEM.
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
    ).add_extension(
        # Generalmente, para certificados de usuario final, no se necesita SAN (DNSName),
        # pero es buena práctica para incluir el correo como SAN (RFC 5280) si lo deseas.
        x509.SubjectAlternativeName([
            x509.RFC822Name(correo)
        ]),
        critical=False,
    ).sign(
        clave_privada_usuario,
        hashes.SHA256() # Algoritmo de hash recomendado para la firma del CSR
    )

    # Codificar la CSR a formato PEM para luego guardarla
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    
    return csr_pem


def guardar_csr(usuario_name, csr_pem):
    """Escribe el CSR a un archivo .csr en la carpeta certs/"""
    if not os.path.exists("certs"):
        os.makedirs("certs")
    
    # Escribir la CSR al disco para dársela a la CA (o al proceso de firma)
    with open(f"certs/{usuario_name}.csr", "wb") as f:
        f.write(csr_pem)
    print(f"CSR generado y guardado en certs/{usuario_name}.csr")

""" HASTA AQUÍ SE SUPONE QUE LO DE ARRIBA ESTÁ BIEN"""


""" copia/pega rapido estoy hasta los huevos

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import datetime
import os

# --- Rutas de la CA (Ajustar según tu estructura real si es diferente a la CSR del usuario) ---
RUTA_CERTIFICADO_CA = "AC1/ac1cert.pem"
RUTA_CLAVE_PRIVADA_CA = "AC1/privado/ca1key.pem"
# NOTA: La clave privada de la CA NO debe estar protegida con contraseña en un entorno de CA
# automatizado, o necesitarías gestionar su contraseña. Asumo que está sin cifrar para este ejemplo.
PASSWORD_CA = None # Si tu clave de CA estuviera protegida, úsala aquí

# -----------------------------------------------------------------------------------------

def cargar_certificado_ca():
    Carga el certificado PEM de la CA Raíz.
    try:
        with open(RUTA_CERTIFICADO_CA, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        return cert
    except FileNotFoundError:
        print(f"Error: Certificado de la CA no encontrado en {RUTA_CERTIFICADO_CA}")
        return None

def cargar_clave_ca():
    Carga la clave privada PEM de la CA Raíz.
    try:
        with open(RUTA_CLAVE_PRIVADA_CA, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), PASSWORD_CA, default_backend())
        return key
    except FileNotFoundError:
        print(f"Error: Clave privada de la CA no encontrada en {RUTA_CLAVE_PRIVADA_CA}")
        return None
    except Exception as e:
        print(f"Error al cargar la clave privada de la CA: {e}")
        return None


def firmar_csr_usuario(csr_pem, usuario_name):
    
    Firma una CSR con el certificado y la clave privada de la CA Raíz.

    Args:
        csr_pem (bytes): La CSR del usuario en formato PEM.
        usuario_name (str): Nombre de usuario (para la ruta del certificado final).

    Returns:
        bytes: El certificado final del usuario codificado en formato PEM.
    
    
    # 1. Cargar la CA y la CSR
    ca_cert = cargar_certificado_ca()
    ca_key = cargar_clave_ca()
    
    if ca_cert is None or ca_key is None:
        return None

    try:
        # Cargar la CSR
        csr = x509.load_pem_x509_csr(csr_pem, default_backend())
        if not csr.is_signature_valid:
            print("Error: La firma del CSR es inválida.")
            return None
    except Exception as e:
        print(f"Error al cargar la CSR: {e}")
        return None


    # 2. Definir los parámetros del nuevo certificado
    
    # Serial number: Usamos un número basado en el tiempo actual para asegurar unicidad
    one_day = datetime.timedelta(days=1)
    # Define la fecha de inicio y la fecha de caducidad (ej: 365 días)
    not_before = datetime.datetime.now(datetime.timezone.utc)
    not_after = not_before + datetime.timedelta(days=365) 
    
    # Usamos un número aleatorio para el número de serie (simplificación de CA real)
    import uuid
    serial_number = int(uuid.uuid4().int % (2**64 - 1)) 


    # 3. Construir el certificado
    builder = x509.CertificateBuilder().subject_name(
        csr.subject # Hereda el Subject Name (información del usuario) de la CSR
    ).issuer_name(
        ca_cert.subject # El emisor es el Subject Name de la CA
    ).public_key(
        csr.public_key() # Hereda la clave pública del usuario de la CSR
    ).serial_number(
        serial_number
    ).not_valid_before(
        not_before
    ).not_valid_after(
        not_after
    )

    # 4. Copiar extensiones de la CSR al certificado (ej: Subject Alternative Name)
    for extension in csr.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
        
    # 5. Agregar extensiones específicas de certificado (Key Usage, Basic Constraints, etc.)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), # Es un certificado de entidad final
        critical=True,
    )
    # Nota: También deberías añadir Key Usage (ej: Digital Signature, Non Repudiation)

    # 6. Firmar el certificado con la clave privada de la CA
    certificado_usuario = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    # 7. Serializar el certificado a PEM
    cert_pem = certificado_usuario.public_bytes(serialization.Encoding.PEM)

    # 8. Guardar el certificado en disco
    if not os.path.exists("certs_usuarios"):
        os.makedirs("certs_usuarios")
    with open(f"certs_usuarios/{usuario_name}_cert.pem", "wb") as f:
        f.write(cert_pem)
        
    print(f"Certificado firmado y guardado en certs_usuarios/{usuario_name}_cert.pem")

    return cert_pem"""