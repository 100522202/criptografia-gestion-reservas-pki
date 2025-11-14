import os
import json
from typing import Optional
from base64 import b64decode, b64encode
from tkinter import messagebox

import hash_functions
import key_management
import signing
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


RESERVAS_FILE = "database/reservas.json"


class Booking:
    def __init__(self, usuario_asociado: str, datos: str, fecha_asociada: str):
        self.usuario_asociado = usuario_asociado
        self.datos = datos
        self.fecha_asociada = fecha_asociada

    def cifrar_reserva(self, clave_privada_firma) -> dict:
        """Firma y cifra la reserva de manera híbrida (AES-GCM + RSA-OAEP)."""
        if clave_privada_firma is None:
            raise ValueError("Se necesita la clave privada para firmar la reserva.")

        datos_completos = [self.usuario_asociado, self.fecha_asociada, self.datos]
        datos_json = json.dumps(datos_completos)

        usuario_hasheado = hash_functions.hash_text(self.usuario_asociado)
        datos_bytes = datos_json.encode()
        usuario_bytes = self.usuario_asociado.encode()

        # Firmamos en claro antes de cifrar para preservar la integridad
        firma = signing.firmar_reserva(clave_privada_firma, datos_json)

        # AES-GCM para confidencialidad e integridad simétrica
        aes_clave = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(aes_clave)
        nonce = os.urandom(12)

        print(f"[DEBUG] booking_management: -- Inicio cifrado reserva para {self.usuario_asociado} --")
        reserva_cifrada = aesgcm.encrypt(nonce, datos_bytes, associated_data=usuario_bytes)
        print(
            f"[DEBUG] booking_management: AES-GCM completado -> ciphertext={len(reserva_cifrada)} bytes."
        )

        # Protegemos la clave AES con RSA-OAEP para el usuario y el admin
        clave_publica_usuario = key_management.cargar_clave_publica(self.usuario_asociado)
        aes_clave_cifrada = key_management.rsa_oaep_encrypt(clave_publica_usuario, aes_clave)
        print("[DEBUG] booking_management: Clave AES protegida con RSA-OAEP para el usuario.")

        clave_publica_admin = key_management.cargar_clave_publica("admin")
        aes_clave_cifrada_admin = key_management.rsa_oaep_encrypt(clave_publica_admin, aes_clave)
        usuario_cifrado_admin = key_management.rsa_oaep_encrypt(
            clave_publica_admin,
            self.usuario_asociado.encode(),
        )
        print("[DEBUG] booking_management: Clave AES y titular duplicados para admin.")
        print("[DEBUG] booking_management: -- Fin cifrado reserva --")

        return {
            "usuario_hasheado": usuario_hasheado,
            "reserva_cifrada": reserva_cifrada,
            "aes_clave_cifrada": aes_clave_cifrada,
            "aes_clave_cifrada_admin": aes_clave_cifrada_admin,
            "nonce": nonce,
            "usuario_original_cifrado": usuario_cifrado_admin,
            "firma": firma,
        }


def descifrar_reserva(
    reserva: dict,
    usuario_name: str,
    password: str,
    clave_privada: Optional[object] = None,
) -> list:
    """
    Descifra y valida una reserva protegida con AES-GCM + RSA y firma RSA-PSS.
    Devuelve los datos de la reserva como lista [usuario, fecha, datos_json].
    """
    if clave_privada is None:
        clave_privada = key_management.cargar_clave_privada(usuario_name, password)
    print(f"[DEBUG] booking_management: -- Inicio descifrado reserva para {usuario_name} --")

    if usuario_name == "admin" and "aes_clave_cifrada_admin" in reserva:
        aes_clave_cifrada_bytes = b64decode(reserva["aes_clave_cifrada_admin"])
    else:
        aes_clave_cifrada_bytes = b64decode(reserva["aes_clave_cifrada"])

    clave_aes = key_management.rsa_oaep_decrypt(clave_privada, aes_clave_cifrada_bytes)
    origen_clave = (
        "admin" if usuario_name == "admin" and "aes_clave_cifrada_admin" in reserva else usuario_name
    )
    print(
        f"[DEBUG] booking_management: Clave AES recuperada mediante RSA-OAEP (destinada a {origen_clave})."
    )

    aesgcm = AESGCM(clave_aes)
    nonce = b64decode(reserva["nonce"])
    reserva_cifrada_bytes = b64decode(reserva["reserva_cifrada"])

    if usuario_name == "admin":
        usuario_cifrado_b64 = reserva.get("usuario_original_cifrado")
        if not usuario_cifrado_b64:
            raise ValueError("Reserva sin titular cifrado para el administrador.")
        titular_bytes = key_management.rsa_oaep_decrypt(
            clave_privada,
            b64decode(usuario_cifrado_b64),
        )
        usuario_asociado = titular_bytes.decode()
        print("[DEBUG] booking_management: Titular original recuperado usando la clave del admin.")
    else:
        usuario_asociado = usuario_name

    datos_descifrados_bytes = aesgcm.decrypt(
        nonce,
        reserva_cifrada_bytes,
        associated_data=usuario_asociado.encode(),
    )
    print("[DEBUG] booking_management: AES-GCM descifrado correctamente.")

    datos_descifrados_str = datos_descifrados_bytes.decode("utf-8")
    datos_descifrados = json.loads(datos_descifrados_str)

    firma_b64 = reserva.get("firma")
    if not firma_b64:
        raise ValueError("Reserva sin firma almacenada; se descarta.")
    firma = b64decode(firma_b64)

    if isinstance(datos_descifrados, list) and datos_descifrados:
        titular_para_firma = datos_descifrados[0]
    elif isinstance(datos_descifrados, dict):
        titular_para_firma = datos_descifrados.get("usuario_asociado")
    else:
        titular_para_firma = None
    if not titular_para_firma:
        raise ValueError("Titular no encontrado en los datos descifrados.")

    clave_publica_titular = key_management.cargar_clave_publica(titular_para_firma)
    if not signing.verificar_firma(clave_publica_titular, datos_descifrados_str, firma):
        raise ValueError("Firma inválida tras descifrar; reserva descartada.")

    print("[DEBUG] booking_management: Firma RSA-PSS validada correctamente.")
    print("[DEBUG] booking_management: -- Fin descifrado reserva --")
    return datos_descifrados


def almacenar_reserva(reserva_cifrada: dict, ruta_archivo: str) -> bool:
    """Guarda la reserva cifrada en JSON codificando todo en Base64."""
    if not is_encrypted(reserva_cifrada):
        return False

    datos_a_guardar = {
        "usuario_hasheado": reserva_cifrada["usuario_hasheado"],
        "reserva_cifrada": bytes_a_base64(reserva_cifrada["reserva_cifrada"]),
        "aes_clave_cifrada": bytes_a_base64(reserva_cifrada["aes_clave_cifrada"]),
        "aes_clave_cifrada_admin": bytes_a_base64(reserva_cifrada["aes_clave_cifrada_admin"]),
        "nonce": bytes_a_base64(reserva_cifrada["nonce"]),
        "usuario_original_cifrado": bytes_a_base64(reserva_cifrada["usuario_original_cifrado"]),
        "firma": bytes_a_base64(reserva_cifrada["firma"]),
    }

    if os.path.exists(ruta_archivo):
        with open(ruta_archivo, "r", encoding="utf-8") as f:
            try:
                todas_las_reservas = json.load(f)
            except json.JSONDecodeError:
                todas_las_reservas = []
    else:
        todas_las_reservas = []

    todas_las_reservas.append(datos_a_guardar)
    with open(ruta_archivo, "w", encoding="utf-8") as f:
        json.dump(todas_las_reservas, f, indent=4)

    print(
        f"[INFO] booking_management: Reserva almacenada (ciphertext={len(reserva_cifrada['reserva_cifrada'])} bytes)."
    )
    return True


def obtener_reservas(usuario_asociado: str, password: str) -> list:
    """Recupera y descifra todas las reservas asociadas al usuario."""
    if not os.path.exists(RESERVAS_FILE):
        return []

    with open(RESERVAS_FILE, "r", encoding="utf-8") as f:
        try:
            todas_las_reservas = json.load(f)
        except json.JSONDecodeError:
            return []

    if usuario_asociado == "admin":
        return obtener_todas_reservas("admin", password)

    reservas_usuario = []
    clave_privada_usuario = None
    for idx, reserva in enumerate(todas_las_reservas, start=1):
        try:
            usuario_hasheado_guardado = reserva.get("usuario_hasheado")
            if not usuario_hasheado_guardado:
                continue
            if not hash_functions.verify_hash(usuario_asociado, usuario_hasheado_guardado):
                print(
                    f"[DEBUG] booking_management: Argon2id no coincide para usuario {usuario_asociado}; reserva omitida."
                )
                continue
            if clave_privada_usuario is None:
                clave_privada_usuario = key_management.cargar_clave_privada(
                    usuario_asociado,
                    password,
                )
            datos = descifrar_reserva(
                reserva,
                usuario_asociado,
                password,
                clave_privada=clave_privada_usuario,
            )
            reservas_usuario.append(datos)
            print(f"[DEBUG] booking_management: Reserva #{idx} descifrada para {usuario_asociado}.")
        except Exception as exc:
            print(f"[WARN] booking_management: Reserva #{idx} descartada -> {exc}")
            continue

    return reservas_usuario


def obtener_todas_reservas(usuario_admin: str, password_admin: str) -> list:
    """Descifra todas las reservas utilizando la clave privada del administrador."""
    if usuario_admin != "admin":
        return []

    if not os.path.exists(RESERVAS_FILE):
        return []

    with open(RESERVAS_FILE, "r", encoding="utf-8") as f:
        try:
            todas_las_reservas = json.load(f)
        except json.JSONDecodeError:
            return []

    resultado = []
    clave_privada_admin_cache = key_management.cargar_clave_privada("admin", password_admin)
    print("[DEBUG] booking_management: -- Inicio descifrado total como admin --")
    for idx, reserva in enumerate(todas_las_reservas, start=1):
        try:
            datos = descifrar_reserva(
                reserva,
                "admin",
                password_admin,
                clave_privada=clave_privada_admin_cache,
            )
            resultado.append(datos)
            print(f"[DEBUG] booking_management: Reserva administrativa #{idx} descifrada.")
        except Exception as exc:
            print(f"[WARN] booking_management: Reserva admin #{idx} descartada -> {exc}")
            continue
    print("[DEBUG] booking_management: -- Fin descifrado total como admin --")

    return resultado


def is_encrypted(reserva: dict) -> bool:
    """Comprueba si el diccionario tiene todos los campos esperados."""
    if not isinstance(reserva, dict):
        return False
    required_keys = {
        "reserva_cifrada",
        "aes_clave_cifrada",
        "aes_clave_cifrada_admin",
        "nonce",
        "usuario_original_cifrado",
        "firma",
    }
    return required_keys.issubset(reserva)


def bytes_a_base64(data: bytes) -> str:
    """Convierte bytes a string Base64."""
    return b64encode(data).decode()


def guardar_reserva(usuario, password, email, telefono, dni, fecha, ventana_crear):
    """Crea, firma y cifra una reserva a partir de los datos de la UI."""
    if not all([email, telefono, dni, fecha]):
        messagebox.showwarning("Campos vacíos", "Debes completar todos los campos obligatorios.")
        return

    try:
        datos = {
            "email": email,
            "telefono": telefono,
            "dni": dni,
        }
        booking = Booking(usuario, json.dumps(datos), fecha)
        clave_privada_usuario = key_management.cargar_clave_privada(usuario, password)
        reserva_cifrada = booking.cifrar_reserva(clave_privada_usuario)
        almacenar_reserva(reserva_cifrada, RESERVAS_FILE)

        messagebox.showinfo("Éxito", "Reserva creada, firmada y cifrada correctamente.")
        ventana_crear.destroy()
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo crear la reserva:\n{e}")
