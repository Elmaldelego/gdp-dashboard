import streamlit as st
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Funciones de cifrado y descifrado
def encrypt_message(message, key):
    key = key.encode('utf-8')  # Convertir la clave a bytes
    message = message.encode('utf-8')  # Convertir el mensaje a bytes
    cipher = AES.new(key, AES.MODE_CBC)  # Inicializar el cifrador AES en modo CBC
    ct_bytes = cipher.encrypt(pad(message, AES.block_size))  # Encriptar el mensaje con padding
    iv = base64.b64encode(cipher.iv).decode('utf-8')  # Codificar el IV en base64
    ct = base64.b64encode(ct_bytes).decode('utf-8')  # Codificar el texto cifrado en base64
    return f"{iv}:{ct}"

def decrypt_message(encrypted_message, key):
    try:
        key = key.encode('utf-8')
        iv, ct = encrypted_message.split(":")  # Separar el IV y el texto cifrado
        iv = base64.b64decode(iv)  # Decodificar el IV desde base64
        ct = base64.b64decode(ct)  # Decodificar el texto cifrado desde base64
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)  # Descifrar y quitar el padding
        return pt.decode('utf-8')
    except (ValueError, KeyError) as e:
        return "Error al descifrar. Verifica la clave o el texto encriptado."

# Configuración de la app en Streamlit
st.title("Encriptador y Desencriptador AES")
st.write("Usa una clave de 16 caracteres para cifrar y descifrar tus mensajes.")

# Entradas del usuario
option = st.selectbox("Elige una opción:", ("Encriptar", "Desencriptar"))
message = st.text_area("Introduce el mensaje")
key = st.text_input("Clave de 16 caracteres", max_chars=16, type="password")

if st.button("Ejecutar"):
    if len(key) != 16:
        st.error("La clave debe tener 16 caracteres.")
    else:
        if option == "Encriptar":
            encrypted_message = encrypt_message(message, key)
            st.success("Mensaje Encriptado:")
            st.code(encrypted_message)
        else:
            decrypted_message = decrypt_message(message, key)
            st.success("Mensaje Desencriptado:")
            st.code(decrypted_message)
