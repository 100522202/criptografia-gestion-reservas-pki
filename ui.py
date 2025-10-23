import tkinter as tk
import json
import user_management
import booking_management
from tkinter import messagebox, ttk
from login import login_usuario


USUARIOS_FILE = "database/usuarios.json"

class Interfaz:
    def __init__(self, root):
        self.root = root
        self.root.title("App de Reservas — Login / Registro")
        self.root.geometry("400x460")
        self.root.configure(bg="#e6f2ff")  # Fondo de la ventana

        self.usuarios = user_management.cargar_usuarios()

        self.main_frame = tk.Frame(self.root, bg="#e6f2ff")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self._mostrar_login()

    def limpiar_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def _estilo_entry(self, entry):
        entry.config(
            font=("Arial", 11),
            bd=2,
            relief="groove",
            highlightbackground="#b3d9ff",
            highlightthickness=1
        )

    def _mostrar_login(self):
        self.limpiar_frame()

        tk.Label(self.main_frame, text="Iniciar Sesión", font=("Arial", 18, "bold"), bg="#e6f2ff").pack(pady=20)
        
        tk.Label(self.main_frame, text="Usuario:", bg="#e6f2ff").pack()
        self.login_usuario = tk.Entry(self.main_frame)
        self._estilo_entry(self.login_usuario)
        self.login_usuario.pack(pady=5)

        tk.Label(self.main_frame, text="Contraseña:", bg="#e6f2ff").pack()
        self.login_password = tk.Entry(self.main_frame, show="*")
        self._estilo_entry(self.login_password)
        self.login_password.pack(pady=5)

        tk.Button(self.main_frame, text="Entrar", bg="#4da6ff", fg="white",
                  font=("Arial", 11), command=self._accion_login).pack(pady=15)

        tk.Button(self.main_frame, text="Ir a Registro", bg="#d9d9d9",
                  font=("Arial", 10), command=self._mostrar_registro).pack()

    def _mostrar_registro(self):
        self.limpiar_frame()

        tk.Label(self.main_frame, text="Registro de Usuario", font=("Arial", 18, "bold"), bg="#e6f2ff").pack(pady=20)

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
            tk.Label(self.main_frame, text=f"{label}:", bg="#e6f2ff").pack()
            entry = tk.Entry(self.main_frame, show=extra[0] if extra else "")
            self._estilo_entry(entry)
            entry.pack(pady=4)
            self.registro_campos[clave] = entry

        tk.Button(self.main_frame, text="Registrar", bg="#4da6ff", fg="white",
                  font=("Arial", 11), command=self._accion_registro).pack(pady=15)

        tk.Button(self.main_frame, text="Ir a Login", bg="#d9d9d9",
                  font=("Arial", 10), command=self._mostrar_login).pack()

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
            # Crear nueva ventana para mostrar las reservas
            self._mostrar_reservas(usuario)
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

        exito, mensaje = user_management.registro_usuario(usuario, pw1, nombre, apellidos, correo)
        if exito:
            self.usuarios = user_management.cargar_usuarios()
            messagebox.showinfo("Registro correcto", mensaje)
            self._mostrar_login()
        else:
            messagebox.showerror("Error", mensaje)
    
    def _mostrar_reservas(self, usuario):
        """Crea una nueva ventana y muestra las reservas almacenadas"""
        ventana_reservas = tk.Toplevel(self.root)
        ventana_reservas.title(f"Reservas de {usuario}")
        ventana_reservas.geometry("500x400")

        tk.Label(ventana_reservas, text=f"Reservas del usuario {usuario}", font=("Arial", 14, "bold")).pack(pady=10)

        # Intentar cargar las reservas del archivo
        try:
            with open("reservas.json", "r") as f:
                reservas = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            reservas = []

        # Si no hay reservas, mostrar mensaje
        if not reservas:
            tk.Label(
                ventana_reservas,
                text="No hay reservas almacenadas.",
                font=("Arial", 12)
            ).pack(pady=20)
        else:
            # Crear un Treeview para mostrar las reservas
            tree = ttk.Treeview(
                ventana_reservas,
                columns=("reserva", "clave", "nonce"),
                show="headings"
            )
            tree.heading("reserva", text="Reserva cifrada")
            tree.heading("clave", text="Clave AES cifrada")
            tree.heading("nonce", text="Nonce")

            # Ajustar ancho de columnas
            tree.column("reserva", width=150)
            tree.column("clave", width=150)
            tree.column("nonce", width=150)

            # Insertar cada reserva en la tabla
            for r in reservas:
                tree.insert(
                    "",
                    tk.END,
                    values=(
                        r["reserva_cifrada"][:20] + "...",
                        r["aes_clave_cifrada"][:20] + "...",
                        r["nonce"][:20] + "..."
                    )
                )

            tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Botón para crear una nueva reserva
        boton_nueva = tk.Button(
            ventana_reservas,
            text="Crear nueva reserva",
            font=("Arial", 12, "bold"),
            bg="#4CAF50",
            fg="white",
            padx=10,
            pady=5,
            command=lambda: self._abrir_crear_reserva(usuario)
        )
        boton_nueva.pack(pady=10)
    
    def _abrir_crear_reserva(self, usuario):
        """Crea una ventana para introducir una nueva reserva, cifrarla y almacenarla."""
        ventana_crear = tk.Toplevel(self.root)
        ventana_crear.title(f"Nueva reserva - {usuario}")
        ventana_crear.geometry("400x500")

        tk.Label(
            ventana_crear,
            text="Introduce los datos de la reserva:",
            font=("Arial", 12, "bold")
        ).pack(pady=10)

        marco_datos = tk.Frame(ventana_crear)
        marco_datos.pack(pady=10)

        # Campos individuales
        tk.Label(marco_datos, text="Email:", font=("Arial", 10)).grid(row=0, column=0, sticky="e", padx=5, pady=5)
        entry_email = tk.Entry(marco_datos, width=30)
        entry_email.grid(row=0, column=1, pady=5)

        tk.Label(marco_datos, text="Teléfono:", font=("Arial", 10)).grid(row=1, column=0, sticky="e", padx=5, pady=5)
        entry_telefono = tk.Entry(marco_datos, width=30)
        entry_telefono.grid(row=1, column=1, pady=5)

        tk.Label(marco_datos, text="DNI:", font=("Arial", 10)).grid(row=2, column=0, sticky="e", padx=5, pady=5)
        entry_dni = tk.Entry(marco_datos, width=30)
        entry_dni.grid(row=2, column=1, pady=5)

        tk.Label(marco_datos, text="Fecha (YYYY-MM-DD):", font=("Arial", 10)).grid(row=3, column=0, sticky="e", padx=5, pady=5)
        entry_fecha = tk.Entry(marco_datos, width=30)
        entry_fecha.grid(row=3, column=1, pady=5)

        # Detalles adicionales
        tk.Label(
            ventana_crear,
            text="Detalles adicionales:",
            font=("Arial", 10)
        ).pack(pady=5)
        entry_detalles = tk.Text(ventana_crear, height=5, width=40)
        entry_detalles.pack(pady=5)

        # --- Botón "Reservar" ---
        boton_reservar = tk.Button(
            ventana_crear,
            text="Reservar",
            font=("Arial", 12, "bold"),
            bg="#4CAF50",
            fg="white",
            padx=10,
            pady=5,
            command=lambda: booking_management.guardar_reserva(
                usuario,
                entry_email.get().strip(),
                entry_telefono.get().strip(),
                entry_dni.get().strip(),
                entry_fecha.get().strip(),
                entry_detalles.get('1.0', tk.END).strip(),
                ventana_crear
            )
        )
        boton_reservar.pack(pady=15)