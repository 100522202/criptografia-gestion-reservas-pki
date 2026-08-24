# Sistema Seguro de Gestión de Reservas con PKI - Criptografía y Seguridad

Práctica de la asignatura **Criptografía y Seguridad Informática (UC3M)**.

---

## Descripción del Proyecto

Aplicación de escritorio en **Python (Tkinter)** que implementa un sistema integral de seguridad y privacidad para la gestión y almacenamiento de reservas.

### Mecanismos Criptográficos Implementados:
* **Autenticación Robusta:** Derivación y almacenamiento seguro de contraseñas con **Argon2id** y salting aleatorio.
* **Infraestructura de Clave Pública (PKI):**
  * Autoridad de Certificación propia (**AC1**) con par de claves RSA raíz y certificado autofirmado X.509.
  * Emisión, firma y verificación de certificados digitales de usuario a partir de solicitudes CSR.
* **Cifrado Híbrido (Confidencialidad):**
  * Cifrado simétrico de los datos de reserva con **AES-GCM / AES-CBC** usando una clave de sesión efímera.
  * Cifrado asimétrico de la clave de sesión con la clave pública **RSA-OAEP** del usuario.
* **Firma Digital (Integridad y No Repudio):** Firma de transacciones con **RSA-PSS/SHA-256** y verificación contra el certificado digital.

---

## Ejecución

```bash
# Instalar dependencias
pip install cryptography

# Iniciar la aplicación
python main.py
```
