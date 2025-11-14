from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

def firmar_reserva(clave_privada, reserva) -> bytes:
    """Firmamos una reserva utilizando la clave privada de un usuario.
    Se devuelve la reserva firmada."""
    # Pasamos la reserva a bytes
    mensaje = reserva.encode()


    # RSA con PSS es seguro porque añade un padding probabilístico con salt aleatoria,
    # haciendo cada firma única e impredecible. Además, protege contra ataques
    # criptográficos modernos y es el esquema recomendado por NIST y RFC 8017.

    firma = clave_privada.sign(
        mensaje,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # Firma será un objeto tipo bytes
    return firma

def verificar_firma(clave_publica, reserva, firma: bytes) -> bool:
    """ Verificamos la firma sobre la reserva mediante la clave pública del usuario. 
    Se devuelve True si efectivamente la firma pertenece al usuario, 
    False eoc."""

    # Pasamos la reserva a bytes
    mensaje = reserva.encode()

    try:
        clave_publica.verify(
            firma,
            mensaje,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS_MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        # Cualquier otro error inesperado -> False
        return False



