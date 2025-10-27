from ui import Interfaz
import tkinter as tk
from user_management import crear_admin_seguro

def main():

    #Creamos el admin si no existe
    crear_admin_seguro()
    root = tk.Tk()
    app = Interfaz(root)
    root.mainloop()


if __name__ == "__main__":
    main()