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
# TODO: ¿habría que quitar de aquí lo de password y hacerlo de otra forma?
PASSWORD_CA = b"yebenes" # load_pem_private_key() requiere la función en bytes

def generar_csr_usuario(usuario_name, nombre, apellidos, correo, clave_publica_usuario) -> bytes:
    """
    Genera una Solicitud de Firma de Certificado (CSR) utilizando la clave privada
    y los datos del usuario, siguiendo el patrón de cryptography.
    
    Devuelve la CSR codificada en formato PEM.
    """
    if clave_publica_usuario is None:
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
        clave_publica_usuario,
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

""" HASTA AQUÍ SE SUPONE QUE LO DE ARRIBA ESTÁ BIEN"""

def cargar_certificado_ca():
    """Carga el certificado PEM de la CA Raíz."""
    try:
        with open(RUTA_CERTIFICADO_CA, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        return cert
    except FileNotFoundError:
        print(f"Error: Certificado de la CA no encontrado en {RUTA_CERTIFICADO_CA}")
        return None

def cargar_clave_ca():
    """Carga la clave privada PEM de la CA Raíz."""
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


def firmar_csr_usuario(csr_pem:bytes, usuario_name:str):
    
    """Firma una CSR con el certificado y la clave privada de la CA Raíz.

    Args:
        csr_pem (bytes): La CSR del usuario en formato PEM.
        usuario_name (str): Nombre de usuario (para la ruta del certificado final).

    Returns:
        bytes: El certificado final del usuario codificado en formato PEM."""
    
    
    # Cargamos la CA y la CSR
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


    # Definiremos ahora los parámetros del nuevo certificado
    
    # Fecha de inicio y la fecha de caducidad (ej: 365 días)
    not_before = datetime.datetime.now(datetime.timezone.utc)
    not_after = not_before + datetime.timedelta(days=365) 

    # Construir el certificado
    builder = x509.CertificateBuilder().subject_name(
        csr.subject # Coge el Subject Name (información del usuario) de la CSR
    ).issuer_name(
        ca_cert.subject # El emisor es el Subject Name de la CA
    ).public_key(
        csr.public_key() # Extrae la clave pública del usuario directamente de la CSR
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        not_before
    ).not_valid_after(
        not_after
    )

    # Copiar extensiones (la información adicional) de la CSR al certificado X509
    for extension in csr.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    
    #TODO: Resumir comments, los he puesto para entender de primeras

    """Lo hacemos con un bucle porque el código actúa como una CA y debe copiar las 
    extensiones solicitadas por el usuario (como el Subject Alternative Name) desde la CSR al certificado final.
    No lo hacemos como en el ejemplo  de cryptography porque ese método no lee datos de una solicitud externa (CSR).
    Simplemente crea un certificado nuevo y autodefine sus extensiones, cosa que no hace una CA al firmar a un tercero."""

    # Agregar extensiones específicas de certificado (Key Usage, Basic Constraints)

    builder = builder.add_extension(
    # ca=False: Indica que este certificado NO es una Autoridad de Certificación
    # path_length=None: Si ca=False, este campo se ignora.
    x509.BasicConstraints(ca=False, path_length=None), 
    critical=True,
    )

    """El parámetro critical=True significa que la extensión contiene una regla de seguridad fundamental que el software de validación (navegador, servidor...) debe entender y procesar.

    Si un sistema encuentra una extensión marcada como critical=True y no sabe qué significa, debe
    rechazar el certificado inmediatamente por motivos de seguridad. Si fuera critical=False, el
    sistema podría ignorarla de forma segura."""

    # Define para qué fines criptográficos se puede usar la clave pública asociada.
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True, # Permite usar la clave para crear firmas digitales (para TLS)
            key_encipherment=True, # Permite usar la clave para cifrar otras claves
            data_encipherment=False, # Prohibimos usar esta clave directamente para cifrar datos de la aplicación
            content_commitment=False, # Prohibimos usar esta clave para la no-repudiación (para probar autoría legalmente)
            key_cert_sign=False, # NO es una CA -> prohibimos que firme otros certificados
            crl_sign=False, # Prohibimos que este certificado se use para firmar Listas de Revocación (CRL)
            encipher_only=False, # No se permite usar la clave solo para cifrar en condiciones especiales.
            decipher_only=False, # No se permite usar la clave solo para descifrar en condiciones especiales.
            key_agreement=False # No permitimos intercambiar material criptográfico
        ),
        critical=True # También debe ser crítica.
    )

    # Firmamos el certificado con la clave privada de la CA
    # Builder contiene todos los datos definidos antes
    # Flujo:
    # 1 - OpenSSL aplica el hash SHA-256 a los datos
    # 2 - Se cifra ese hash usando la clave privada de la CA/AC
    # 3 - Se obtiene la firma digital de la CA, que se adjunta al certificado del usuario
    certificado_usuario = builder.sign( 
        private_key=ca_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    print(f"[DEBUG] Certificado X.509 firmado con éxito por la CA usando algoritmo SHA-256")

    # Codificar el certificado a PEM
    cert_pem = certificado_usuario.public_bytes(serialization.Encoding.PEM)

    # Guardar el certificado en disco
    if not os.path.exists("certs_usuarios"):
        os.makedirs("certs_usuarios")
    with open(f"certs_usuarios/{usuario_name}_cert.pem", "wb") as f:
        f.write(cert_pem)
        
    print(f"Certificado firmado y guardado en certs_usuarios/{usuario_name}_cert.pem")

    return cert_pem