""" Funciones relacionadas con el registro de usuario"""
import json
import os
import certificate_management as cm
import tkinter as tk
from tkinter import simpledialog, messagebox
import hash_functions
from hash_functions import hash_text
from key_management import generar_par_claves, cargar_clave_privada



USUARIOS_FILE = "database/usuarios.json"

def crear_admin_seguro():
    """Crea el usuario admin de forma segura: no guarda la contraseña
    en el código y solo lo crea si no lo existe, cifra la clave privada 
    con la contraseña introducida"""

    usuarios = cargar_usuarios()
    if "admin" in usuarios:
        return
    
    # Ventana para pedir la contraseña
    root = tk.Tk()
    root.withdraw()  # Oculta la ventana principal

    password1 = simpledialog.askstring(
        "Crear administrador", "Introduce la contraseña del admin:", show="*"
    )
    if password1 is None:
        messagebox.showinfo("Cancelado", "Operación cancelada.")
        return

    password2 = simpledialog.askstring(
        "Confirmar contraseña", "Repite la contraseña:", show="*"
    )
    if password2 is None:
        messagebox.showinfo("Cancelado", "Operación cancelada.")
        return

    if password1 != password2:
        messagebox.showerror("Error", "Las contraseñas no coinciden.")
        return
    
    #hasheamos la contraseña
    hash_psw = hash_text(password1)

    #Guardamos el usuario admin
    usuarios["admin"] = {
       "usuario_name": "admin",
       "nombre": "Administrador",
       "apellidos": "",
       "correo_electronico": "admin@hotel.com",
       "password_hash": hash_psw,
       "rol": "admin"
    }

    generar_par_claves("admin", password1)
    guardar_usuarios(usuarios)

    #Para que nadie pueda modificarlo o leer la clave privada
    try:
        os.chmod("claves/admin_private.pem", 0o600)
        os.chmod("claves/admin_public.pem", 0o644)
    except Exception:
        pass

    messagebox.showinfo("Éxito", "Administrador creado correctamente.")

    root.destroy()



def cargar_usuarios():
    if not os.path.exists(USUARIOS_FILE):
        return {}
    with open(USUARIOS_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def guardar_usuarios(usuarios):
    with open(USUARIOS_FILE, "w", encoding="utf-8") as f:
        json.dump(usuarios, f, indent=2)

def registro_usuario(usuario_name, password, nombre, apellidos, correo):
    hash_psw = hash_functions.hash_text(password)

    usuarios = cargar_usuarios()

    if usuario_name in usuarios:
        return False, "El usuario ya existe"

    usuarios[usuario_name] = {
        "rol": "usuario_comun",
        "usuario_name": usuario_name,
        "password_hash": hash_psw,
        "nombre": nombre,
        "apellidos": apellidos,
        "correo_electronico": correo
    }

    generar_par_claves(usuario_name, password)
    clave_privada_usuario = cargar_clave_privada(usuario_name, password)
    #TODO: ¿Luego hay que borrar clave publica.pem?

    # Generamos el csr
    csr_usuario = cm.generar_csr_usuario(usuario_name, nombre, apellidos,correo, clave_privada_usuario)

    
    if csr_usuario:
        # Lo guardamos
        cm.guardar_csr(usuario_name,csr_usuario)
    """ Otro copia/pega barato
    # 5. *** FIRMAR EL CSR CON LA CA ***
        certificado_usuario_pem = firmar_csr_usuario(csr_pem, usuario_name) 

        if certificado_usuario_pem is None:
            return False, "Error al firmar el CSR con la CA."

        # Opcional: Podrías guardar el certificado_usuario_pem en la estructura de 'usuarios'
        usuarios[usuario_name]["certificado"] = certificado_usuario_pem.decode('utf-8')
        
        guardar_usuarios(usuarios)
        return True, "Usuario registrado, claves, CSR y certificado generados correctamente."
    else:
        return False, "Error al generar la CSR."""

    guardar_usuarios(usuarios)

    #Protegemos que otros usuarios no puedan acceder a la informacion de otros en disco
    try:
        os.chmod(f"claves/{usuario_name}_private.pem", 0o600)
        os.chmod(f"claves/{usuario_name}_public.pem", 0o644)
    except Exception:
        pass  # Ignorar en Windows

    return True, "Usuario registrado correctamente."
