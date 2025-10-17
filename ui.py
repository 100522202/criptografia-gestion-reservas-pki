import tkinter as tk
from tkinter import messagebox
from registro import registro_usuario, verify_password
from login import login_usuario
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

class Interfaz:
    def __init__(self, root):
        self.root = root
        self.root.title("App de Reservas — Login / Registro")
        self.root.geometry("400x400")

        self.usuarios = cargar_usuarios()

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

        self.registro_campos = {}
        campos = [
            ("Usuario", "usuario"),
            ("Nombre", "nombre"),
            ("Apellidos", "apellidos"),
            ("Correo electrónico", "correo"),
            ("Contraseña", "pw1", "*"),
            ("Repetir Contraseña", "pw2", "*")
        ]

        for label, clave, *extra in campos:
            tk.Label(self.main_frame, text=f"{label}:").pack()
            entry = tk.Entry(self.main_frame, show=extra[0] if extra else "")
            entry.pack()
            self.registro_campos[clave] = entry

        tk.Button(self.main_frame, text="Registrar", command=self._accion_registro).pack(pady=10)
        tk.Button(self.main_frame, text="Ir a Login", command=self._mostrar_login).pack()

    def _accion_login(self):
        usuario = self.login_usuario.get().strip()
        password = self.login_password.get()
    
        if usuario == "" or password == "":
            messagebox.showwarning("Datos incompletos", "Completa usuario y contraseña")
            return
    
        exito, mensaje = login_usuario(usuario, password)
        if exito:
            messagebox.showinfo("Éxito", mensaje)
            self.login_usuario.delete(0, tk.END)
            self.login_password.delete(0, tk.END)
        else:
            messagebox.showerror("Error", mensaje)


    def _accion_registro(self):
        campos = self.registro_campos
        usuario = campos["usuario"].get().strip()
        nombre = campos["nombre"].get().strip()
        apellidos = campos["apellidos"].get().strip()
        correo = campos["correo"].get().strip()
        pw1 = campos["pw1"].get()
        pw2 = campos["pw2"].get()

        if not all([usuario, nombre, apellidos, correo, pw1, pw2]):
            messagebox.showwarning("Datos incompletos", "Completa todos los campos")
            return

        if pw1 != pw2:
            messagebox.showerror("Error", "Las contraseñas no coinciden")
            return

        exito, mensaje = registro_usuario(usuario, pw1, nombre, apellidos, correo)
        if exito:
            self.usuarios = cargar_usuarios()
            messagebox.showinfo("Registro correcto", mensaje)
            self._mostrar_login()
        else:
            messagebox.showerror("Error", mensaje)

if __name__ == "__main__":
    root = tk.Tk()
    app = Interfaz(root)
    root.mainloop()
