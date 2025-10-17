import tkinter as tk
from tkinter import messagebox
import hashlib
import json
import os

USUARIOS_FILE = "usuarios.json"

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
        json.dump(usuarios, f, indent=4)

def hash_contrasena(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

class Interfaz:
    def __init__(self, root):
        self.root = root
        self.root.title("App de Reservas — Login / Registro")
        self.root.geometry("400x300")
        
        self.usuarios = cargar_usuarios()
        
        # Contenedor principal donde colocamos frames
        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        self._mostrar_login()

    def limpiar_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def _mostrar_login(self):
        self.limpiar_frame()
        
        tk.Label(self.main_frame, text="Login", font=("Arial", 16)).pack(pady=10)
        tk.Label(self.main_frame, text="Usuario:").pack()
        self.login_usuario = tk.Entry(self.main_frame)
        self.login_usuario.pack()
        tk.Label(self.main_frame, text="Contraseña:").pack()
        self.login_password = tk.Entry(self.main_frame, show="*")
        self.login_password.pack()
        
        tk.Button(self.main_frame, text="Entrar", command=self._accion_login).pack(pady=10)
        tk.Button(self.main_frame, text="Ir a Registro", command=self._mostrar_registro).pack()

    def _mostrar_registro(self):
        self.limpiar_frame()
        
        tk.Label(self.main_frame, text="Registro", font=("Arial", 16)).pack(pady=10)
        tk.Label(self.main_frame, text="Usuario:").pack()
        self.registro_usuario = tk.Entry(self.main_frame)
        self.registro_usuario.pack()
        tk.Label(self.main_frame, text="Contraseña:").pack()
        self.registro_password = tk.Entry(self.main_frame, show="*")
        self.registro_password.pack()
        tk.Label(self.main_frame, text="Repetir Contraseña:").pack()
        self.registro_password2 = tk.Entry(self.main_frame, show="*")
        self.registro_password2.pack()
        
        tk.Button(self.main_frame, text="Registrar", command=self._accion_registro).pack(pady=10)
        tk.Button(self.main_frame, text="Ir a Login", command=self._mostrar_login).pack()

    def _accion_login(self):
        usuario = self.login_usuario.get().strip()
        password = self.login_password.get()
        if usuario == "" or password == "":
            messagebox.showwarning("Datos incompletos", "Por favor completa usuario y contraseña")
            return
        
        usuarios = self.usuarios
        if usuario not in usuarios:
            messagebox.showerror("Error", "Usuario no existe")
            return
        
        hash_guardado = usuarios[usuario]["password_hash"]
        if hash_contrasena(password) != hash_guardado:
            messagebox.showerror("Error", "Contraseña incorrecta")
            return
        
        rol = usuarios[usuario].get("role", "user")
        messagebox.showinfo("Éxito", f"Bienvenido, {usuario}. Rol: {rol}")
        # Aquí podrías abrir la ventana principal según rol
        # Por ahora, solo limpiar campos
        self.login_usuario.delete(0, tk.END)
        self.login_password.delete(0, tk.END)

    def _accion_registro(self):
        usuario = self.registro_usuario.get().strip()
        pw1 = self.registro_password.get()
        pw2 = self.registro_password2.get()
        
        if usuario == "" or pw1 == "" or pw2 == "":
            messagebox.showwarning("Datos incompletos", "Completa todos los campos")
            return
        if pw1 != pw2:
            messagebox.showerror("Error", "Las contraseñas no coinciden")
            return
        
        if usuario in self.usuarios:
            messagebox.showerror("Error", "El usuario ya existe")
            return
        
        # Crear nuevo usuario con rol "user" por defecto
        self.usuarios[usuario] = {
            "password_hash": hash_contrasena(pw1),
            "role": "user"
        }
        guardar_usuarios(self.usuarios)
        messagebox.showinfo("Registro correcto", "Usuario creado con éxito")
        
        # Volver al login
        self._mostrar_login()

if __name__ == "__main__":
    root = tk.Tk()
    app = Interfaz(root)
    root.mainloop()
