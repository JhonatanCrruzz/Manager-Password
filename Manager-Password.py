import smtplib
import base64
import hashlib
import os
import json
import re
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from rich.prompt import Prompt
from rich.console import Console
from rich.panel import Panel
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from rich.table import Table
from rich.theme import Theme



console = Console()
custom_theme = Theme({"number": "bold bright_cyan"})
console = Console(theme=custom_theme)

# Archivos donde se guardan los datos
USUARIOS_FILE = "usuarios.json"
SALT_FILE = "salt.bin"

def imprimirseparador():
    console.print("[bold bright_cyan]-" * 50 + "[/bold bright_cyan]"+"\n")  # Separador de 50 guiones en color cyan brillante

def ingresando():
    imprimirseparador()
    console.print("[bold bright_blue]🔜 [/bold bright_blue][bold bright_white]Ingresando.[/bold bright_white]"+"\n")
    imprimirseparador()

def regresando():
    imprimirseparador()
    console.print("[bold bright_blue]🔙[/bold bright_blue][bold bright_white]Regresando.[/bold bright_white]"+"\n")
    imprimirseparador()

# ─────────────────────────────────────────────────────────────────────────────
# 🔐 GENERAR Y CARGAR SALT
# ─────────────────────────────────────────────────────────────────────────────
def cargar_salt():
    """Carga el salt desde un archivo, o lo genera si no existe."""
    if not os.path.exists(SALT_FILE):
        with open(SALT_FILE, "wb") as f:
            f.write(os.urandom(16))
    with open(SALT_FILE, "rb") as f:
        return f.read()

# ─────────────────────────────────────────────────────────────────────────────
# 🔑 DERIVAR CLAVE DE CIFRADO DESDE LA CLAVE MAESTRA
# ─────────────────────────────────────────────────────────────────────────────
def derivar_clave(clave_maestra):
    """Deriva una clave de cifrado desde la clave maestra usando PBKDF2."""
    salt = cargar_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return base64.urlsafe_b64encode(kdf.derive(clave_maestra.encode()))

# ─────────────────────────────────────────────────────────────────────────────
# ✉️ VALIDAR CORREO ELECTRÓNICO
# ─────────────────────────────────────────────────────────────────────────────
def validar_correo(correo):
    """Verifica si un correo tiene un formato válido."""
    correo_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return bool(re.match(correo_regex, correo))

# ─────────────────────────────────────────────────────────────────────────────
# 🔑 VALIDAR CORREO ELECTRÓNICO
# ─────────────────────────────────────────────────────────────────────────────
def validar_clave_maestra(clave):
    """Verifica si la clave maestra cumple con los requisitos de seguridad."""
    if (
        len(clave) < 40  
        or not re.search(r"[A-Z]", clave)  # Al menos una letra mayúscula
        or not re.search(r"[a-z]", clave)  # Al menos una letra minúscula
        or not re.search(r"[\W_]", clave)  # Al menos un carácter especial
    ):
        mensaje = "[bold bright_white]La clave debe tener al menos [bold bright_yellow]40 caracteres[/bold bright_yellow], [bold bright_yellow]una mayúscula[/bold bright_yellow], [bold bright_yellow]una minúscula[/bold bright_yellow] y [bold bright_yellow]un carácter especial[/bold bright_yellow].[/bold bright_white]"
        return False, mensaje  # Devuelve el mensaje como texto, sin imprimirlo aquí
    
    return True, "Clave maestra válida"

# ─────────────────────────────────────────────────────────────────────────────
# 🔑 DECIFRAR CLAVE MAESTRA
# ─────────────────────────────────────────────────────────────────────────────
def descifrar_clave_maestra(clave_cifrada, clave_maestra):
    """Descifra la clave maestra y verifica si coincide con la ingresada."""
    clave_cifrado = Fernet(derivar_clave(clave_maestra))
    try:
        clave_descifrada = clave_cifrado.decrypt(clave_cifrada.encode()).decode()
        return clave_descifrada == clave_maestra
    except:
        return False

# ─────────────────────────────────────────────────────────────────────────────
# 🔒 CIFRAR Y DESCIFRAR CLAVE MAESTRA
# ─────────────────────────────────────────────────────────────────────────────
def cifrar_clave_maestra(clave_maestra):
    """Cifra la clave maestra usando una clave derivada de sí misma."""
    clave_cifrado = Fernet(derivar_clave(clave_maestra))
    clave_cifrada = clave_cifrado.encrypt(clave_maestra.encode())
    return clave_cifrada.decode()

# ─────────────────────────────────────────────────────────────────────────────
# 📁 GUARDAR USUARIO
# ─────────────────────────────────────────────────────────────────────────────
def guardar_usuario(nombre_usuario, correo, clave_maestra):
    """Guarda el usuario con su clave maestra cifrada."""
    usuario = {
        "nombre_usuario": nombre_usuario,
        "correo": correo,
        "clave_maestra_cifrada": cifrar_clave_maestra(clave_maestra)
    }

    # Cargar usuarios existentes
    if os.path.exists(USUARIOS_FILE):
        try:
            with open(USUARIOS_FILE, "r") as f:
                usuarios = json.load(f)
        except json.JSONDecodeError:
            usuarios = []
    else:
        usuarios = []

    # Agregar nuevo usuario
    usuarios.append(usuario)

    # Guardar en el archivo
    with open(USUARIOS_FILE, "w") as f:
        json.dump(usuarios, f, indent=4)

# ─────────────────────────────────────────────────────────────────────────────
# ✅ VERIFICAR CLAVE MAESTRA
# ─────────────────────────────────────────────────────────────────────────────
def verificar_clave_maestra(nombre_usuario, clave_maestra):
    """Verifica si la clave maestra ingresada es correcta para el usuario."""
    if not os.path.exists(USUARIOS_FILE):
        return False

    with open(USUARIOS_FILE, "r") as f:
        usuarios = json.load(f)

    for usuario in usuarios:
        if usuario["nombre_usuario"] == nombre_usuario:
            return descifrar_clave_maestra(usuario["clave_maestra_cifrada"], clave_maestra)

    return False

# ─────────────────────────────────────────────────────────────────────────────
# 👤 OBTENER PERFIL SELECCIONADO
# ─────────────────────────────────────────────────────────────────────────────
def obtener_perfil_seleccionado():
    """Simula la selección de un perfil por el usuario."""
    # Esto es solo un ejemplo, en tu caso esto puede ser diferente
    return "JuanPerez"  # Aquí se debería obtener el nombre del perfil seleccionado

# ─────────────────────────────────────────────────────────────────────────────
# 🔄 MENÚ PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────
def main():
    while True:
        console.print(Panel("[bold bright_Magenta]📌[/bold bright_Magenta] [bold bright_white]MENÚ PRINCIPAL[/bold bright_white] [bold bright_Magenta]📌[/bold bright_Magenta]"))
        print("\n")

        console.print("[bold bright_blue]➖ [/bold bright_blue] [bold bright_white]Bienvenido al gestor de contraseñas, ¿Que deseas hacer?[/bold bright_white]"+"\n")

        console.print("[1] Iniciar sesión")
        console.print("[2] Registrarme"+"\n")
        console.print("[0] Salir"+"\n")

        # Ahora usamos Prompt.ask de forma consistente
        opcion = Prompt.ask("[bold bright_white]Selecciona una opción[/bold bright_white]").strip()

        if opcion == "1":
            ingresando()
            iniciar_sesion()

        elif opcion == "2":
            ingresando()
            submenu_registrousuario()
        
        elif opcion == "0":
            imprimirseparador()
            console.print("[bold bright_yellow]👋[bold bright_yellow] [bold bright_white]Vuelve pronto.[/bold bright_white]"+"\n")
            imprimirseparador()
            exit()
            
        else:
            imprimirseparador()
            console.print("[bold bright_red]❌[bold bright_red] [bold bright_white]Opción inválida. Intenta de nuevo.[/bold bright_white]"+"\n")
            imprimirseparador()

# ─────────────────────────────────────────────────────────────────────────────
# 🔄 SUBMENÚ REGISTRAR USUARIO
# ─────────────────────────────────────────────────────────────────────────────
def submenu_registrousuario():
    while True:

        console.print(Panel("[bold bright_Magenta]📌[/bold bright_Magenta] [bold bright_white]SUBMENÚ REGISTRO USUARIO[/bold bright_white] [bold bright_Magenta]📌[/bold bright_Magenta]"))
        print("\n")

        console.print("[bold bright_blue]➖[/bold bright_blue] [bold bright_white]¿Que deseas hacer?[/bold bright_white]"+"\n")

        console.print("[1] Registrame"+"\n")
        console.print("[0] Volver Atrás"+"\n")


        # Ahora usamos Prompt.ask de forma consistente
        opcion = Prompt.ask("[bold bright_white]Selecciona una opción[/bold bright_white]").strip()


        if opcion == "1":
            ingresando()
            registrar_usuario()
        
        elif opcion == "0":
            regresando()
            main()
                
        else:
            imprimirseparador()
            console.print("[bold bright_red]❌[bold bright_red] [bold bright_white]Opción inválida. Intenta de nuevo.[/bold bright_white]"+"\n")
            imprimirseparador()

# ─────────────────────────────────────────────────────────────────────────────
# 👤 REGISTRAR USUARIO
# ─────────────────────────────────────────────────────────────────────────────
def registrar_usuario():

    console.print(Panel("[bold bright_Magenta]📌[/bold bright_Magenta] [bold bright_white]MODULO REGISTRO NUEVO USUARIO[/bold bright_white] [bold bright_Magenta]📌[/bold bright_Magenta]"))
    print("\n")

    console.print("[bold bright_blue]➖[/bold bright_blue] [bold bright_white]Estas a punto de registrarte, por favor ingresa la información que te solicitamos a continuación.[/bold bright_white]"+"\n")

    # Captura nombre de usuario
    while True:
        nombre_usuario = Prompt.ask("[bold bright_yellow]🧑 Nombre de usuario (Solo letras)[/bold bright_yellow]").strip()
        print("\n")
        if nombre_usuario.isalpha():
            break
        imprimirseparador()
        console.print("[bold bright_red]❌[bold bright_red] [bold bright_white]El nombre de usuario debe contener solo [bold bright_yellow]LETRAS[/bold bright_yellow].[/bold bright_white]"+"\n")
        imprimirseparador()        
            

    # Captura correo
    while True:
        correo = Prompt.ask("[bold bright_white]✉️[/bold bright_white] [bold bright_white] Correo electrónico: [/bold bright_white]").strip()
        print("\n")
        if validar_correo(correo):
            break
        imprimirseparador()
        console.print("[bold bright_red]❌[bold bright_red] [bold bright_white]El correo no tiene el formato correcto [bold bright_yellow]ejemplo@ejemplo.com[/bold bright_yellow].[/bold bright_white]"+"\n")
        imprimirseparador()
            

    # Captura clave maestra
    while True:
        clave_maestra = Prompt.ask("[bold bright_yellow]🔑[bold bright_yellow] [bold bright_white]Clave maestra: [/bold bright_white]").strip()
        print("\n")

        # Validar clave maestra
        es_valida, mensaje = validar_clave_maestra(clave_maestra)
        if es_valida:
            break
        imprimirseparador()
        console.print(f"[bold bright_red]❌[bold bright_red] [bold bright_white]{mensaje}[/bold bright_white]"+"\n")
        imprimirseparador()
        
    while True:        
        clave_maestra_confirmacion = Prompt.ask("[bold bright_yellow]🔑[bold bright_yellow] [bold bright_white]Repita la clave maestra[/bold bright_white]").strip()
        print("\n")
        if clave_maestra == clave_maestra_confirmacion:
            break
        imprimirseparador()
        console.print("[bold bright_red]❌[bold bright_red] [bold bright_white]Las claves no coinciden.[/bold bright_white]"+"\n")
        imprimirseparador()
            

    # Guardar usuario
    guardar_usuario(nombre_usuario, correo, clave_maestra)

    imprimirseparador()
    console.print("[bold bright_green]✅[bold bright_green] [bold bright_white]Registro exitoso.[/bold bright_white]"+"\n")
    imprimirseparador()
    main()

# ─────────────────────────────────────────────────────────────────────────────
# 🔄 SUBMENÚ INICIAR SESIÓN
# ─────────────────────────────────────────────────────────────────────────────
def menu_incio_sesión():
    while True:
        console.print(Panel("[bold bright_Magenta]📌[/bold bright_Magenta] [bold bright_white]SUBMENÚ INCIO DE SESIÓN[/bold bright_white] [bold bright_Magenta]📌[/bold bright_Magenta]"))
        print("\n")

        console.print("[bold bright_blue]➖[/bold bright_blue] [bold bright_white]Me alegra mucho tenerte devuelta, ¿Que deseas hacer hoy?.[/bold bright_white]"+"\n")

        console.print("[1] Iniciar sesión"+"\n")
        console.print("[0] Volver atrás"+"\n")
        # Ahora usamos Prompt.ask de forma consistente
        opcion = Prompt.ask("[bold bright_white]Selecciona una opción[/bold bright_white]").strip()

        if opcion == "0":
            regresando()
            main()

        if opcion == "1":
            ingresando()
            listar_perfiles()

# ─────────────────────────────────────────────────────────────────────────────
# 🔄 LISTAR PERFILES
# ─────────────────────────────────────────────────────────────────────────────
def listar_perfiles():
    """Muestra los perfiles disponibles y permite seleccionar uno."""
    if not os.path.exists(USUARIOS_FILE):

        imprimirseparador()
        console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]No hay perfiles registrados.[/bold bright_white]"+"\n")
        imprimirseparador()
        return None

    with open(USUARIOS_FILE, "r") as f:
        try:
            usuarios = json.load(f)
        except json.JSONDecodeError:
            console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]Error al leer el archivo de usuarios.[/bold bright_white]")
            return None

    if not usuarios:
        console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]No hay perfiles disponibles.[/bold bright_white]")
        return None

    console.print("\n[bold bright_white]Selecciona una opción:[/bold bright_white]\n")
    
    for i, usuario in enumerate(usuarios, start=1):
        console.print(f"[{i}] {usuario['nombre_usuario']}")

    print("\n")     
    console.print("[0] Volver atrás\n")
    
    seleccion = Prompt.ask("[bold bright_white]Selecciona una opción[/bold bright_white]").strip()
    
    if seleccion == "0":
        regresando()
        main()
        return None
        
    try:
        seleccion = int(seleccion)
        if 1 <= seleccion <= len(usuarios):
            return usuarios[seleccion - 1]["nombre_usuario"]
    except ValueError:
        pass

    imprimirseparador()
    console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]Opción inválida. Intenta de nuevo.[/bold bright_white]"+"\n")
    imprimirseparador()
    listar_perfiles()
    return None

# ─────────────────────────────────────────────────────────────────────────────
# 🔄 INICIAR SESÓN
# ─────────────────────────────────────────────────────────────────────────────
def iniciar_sesion():
    console.print(Panel("[bold bright_Magenta]📌[/bold bright_Magenta] [bold bright_white]INICIO DE SESIÓN[/bold bright_white] [bold bright_Magenta]📌[/bold bright_Magenta]"))
    
    perfil_seleccionado = listar_perfiles()
    if not perfil_seleccionado:
        return

    imprimirseparador()
    console.print("[bold bright_blue]➖[/bold bright_blue] [bold bright_white]Por favor ingresa los datos que te pedimos a continuación, para el inicio de sesión.[/bold bright_white]"+"\n")
    clave_maestra = Prompt.ask("[bold bright_yellow]🔑[/bold bright_yellow] [bold bright_white]Ingrese su clave maestra[/bold bright_white]", password=False).strip()
    print("\n")

    if verificar_clave_maestra(perfil_seleccionado, clave_maestra):
        imprimirseparador()
        console.print(f"[bold bright_green]✅[/bold bright_green] [bold bright_white]Bienvenido, [bold bright_yellow]{perfil_seleccionado}[/bold bright_yellow]![/bold bright_white]"+"\n")
        imprimirseparador()
        menu_perfil(perfil_seleccionado)

    else:
        imprimirseparador()
        console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]Clave incorrecta. Intente de nuevo.[/bold bright_white]"+"\n")
        imprimirseparador()
        iniciar_sesion()

# ─────────────────────────────────────────────────────────────────────────────
# 🔄 MENU PERFIL
# ───────────────────────────────────────────────────────────────────────────── 
def menu_perfil(perfil_seleccionado):
    while True:
        console.print(Panel(f"[bold bright_Magenta]📌[/bold bright_Magenta] [bold bright_white]PERFIL DE [bold bright_yellow]{perfil_seleccionado}[/bold bright_yellow] [/bold bright_white] [bold bright_Magenta]📌[/bold bright_Magenta]"))
        print("\n")
        console.print("[bold bright_blue]➖[/bold bright_blue] [bold bright_white]Me alegra mucho tenerte devuelta, ¿Que deseas hacer hoy?.[/bold bright_white]"+"\n")

        console.print("[1] Añadir credencial")
        console.print("[2] Listar credenciales")
        console.print("[3] Eliminar credencial")
        console.print("[4] Cambiar clave maestra")
        console.print("[5] Actualizar información"+"\n")

        console.print("[0] Salir"+"\n")
        # Ahora usamos Prompt.ask de forma consistente
        opcion = Prompt.ask("[bold bright_white]Selecciona una opción[/bold bright_white]").strip()

        if opcion == "1":
            ingresando()
            menu_añadir_credencial(perfil_seleccionado)
        elif opcion == "2":
            ingresando()
            listar_credenciales(perfil_seleccionado)
        elif opcion == "3":
            ingresando()
            eliminar_credencial(perfil_seleccionado)
        elif opcion == "4":
            ingresando()
            cambio_clave_maestra(perfil_seleccionado)
        elif opcion == "5":
            ingresando()
            actualizar_informacion(perfil_seleccionado)

        elif opcion == "0":

            console.print(f"[bold bright_blue]➖[/bold bright_blue] [bold bright_white]Hasta la prixima [bold bright_yellow]{perfil_seleccionado}[/bold bright_yellow] .[/bold bright_white]"+"\n")
            imprimirseparador()
            main()

        else:
            imprimirseparador()
            console.print("[bold bright_red]❌[bold bright_red] [bold bright_white]Opción inválida. Intenta de nuevo.[/bold bright_white]"+"\n")
            imprimirseparador()
            
# ─────────────────────────────────────────────────────────────────────────────
# 🔄 SUBMENU AÑADIR CREDENCIAL
# ───────────────────────────────────────────────────────────────────────────── 
def menu_añadir_credencial(perfil_seleccionado):
    while True:
        console.print(Panel(f"[bold bright_Magenta]📌[/bold bright_Magenta] [bold bright_white]SUBMENÚ AÑADIR CREDENCIAL PARA [bold bright_yellow]{perfil_seleccionado}[/bold bright_yellow] [/bold bright_white] [bold bright_Magenta]📌[/bold bright_Magenta]"))
        print("\n")
        console.print("[bold bright_blue]➖[/bold bright_blue] [bold bright_white]Confirma qué deseas realizar.[/bold bright_white]\n")

        console.print("[1] Añadir nueva credencial\n")
        console.print("[0] Volver atrás\n")

        opcion = Prompt.ask("[bold bright_white]Selecciona una opción[/bold bright_white]").strip()    

        if opcion == "1":
            ingresando()
            nueva_credencial(perfil_seleccionado)  # Llama la función automáticamente
        elif opcion == "0":
            regresando()
            menu_perfil(perfil_seleccionado)
        
        else:
            imprimirseparador()
            console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]Clave incorrecta. Intente de nuevo.[/bold bright_white]"+"\n")
            imprimirseparador()

# ─────────────────────────────────────────────────────────────────────────────
# 🔄 NUEVA CREDENCIAL
# ───────────────────────────────────────────────────────────────────────────── 
def nueva_credencial(perfil_seleccionado):
    """Añade una nueva credencial al perfil activo automáticamente desde el menú."""

    # Cargar el archivo JSON de usuarios
    if not os.path.exists(USUARIOS_FILE):

        console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]No hay usuarios registrados aún.[/bold bright_white]"+"\n")
        imprimirseparador()
        return

    with open(USUARIOS_FILE, "r") as f:
        try:
            usuarios = json.load(f)
        except json.JSONDecodeError:
            console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]Error al cargar el archivo de usuarios.[/bold bright_white]"+"\n"+"\n")
            imprimirseparador()
            return

    # Buscar el perfil del usuario activo
    perfil = None
    for usuario in usuarios:
        if usuario["nombre_usuario"] == perfil_seleccionado:
            perfil = usuario
            break

    if not perfil:

        console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]Usuario no encontrado.[/bold bright_white]"+"\n")
        imprimirseparador()
        return

    # Solicitar datos de la nueva credencial
    console.print(Panel(f"[bold bright_Magenta]📌[/bold bright_Magenta] [bold bright_white]REGISTRO DE CREDENCIAL PARA [bold bright_yellow]{perfil_seleccionado}[/bold bright_yellow] [/bold bright_white] [bold bright_Magenta]📌[/bold bright_Magenta]"))
    print("\n")
    console.print("[bold bright_blue]➖[/bold bright_blue] [bold bright_white]Estas a punto de realiza el registro de una nueva credencial, por favor ingresa la información que te pedimos a continuación.[/bold bright_white]\n")

    while True:
        servicio = Prompt.ask("[bold bright_blue]🌐[/bold bright_blue] [bold bright_white]Servicio (Ej: Google, Facebook)[/bold bright_white]").strip()
        imprimirseparador()
        if len(servicio) >= 1:
            break
        console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]El nombre del servicio debe tener al menos 1 caracter.[/bold bright_white]"+"\n")
        imprimirseparador()


    while True:
        usuario_servicio = Prompt.ask("[bold bright_green]👤[/bold bright_green] [bold bright_white]Usuario[/bold bright_white]").strip()
        imprimirseparador()
        if len(usuario_servicio) >= 1:
            break
        console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]El nombre del usuario debe tener al menos 1 caracter.[/bold bright_white]"+"\n")
        imprimirseparador()

    while True:
        correo_servicio = Prompt.ask("[bold bright_red]📧[/bold bright_red] [bold bright_white]Correo Eléctronico asociado[/bold bright_white]").strip()
        imprimirseparador()
        if validar_correo(correo_servicio):
            break
        imprimirseparador()
        console.print("[bold bright_red]❌[bold bright_red] [bold bright_white]El correo no tiene el formato correcto [bold bright_yellow]ejemplo@ejemplo.com[/bold bright_yellow].[/bold bright_white]"+"\n")
        imprimirseparador()

    while True:
        contraseña_servicio = Prompt.ask("[bold bright_yellow]🔑[/bold bright_yellow] [bold bright_white]Contraseña[/bold bright_white]", password=False).strip()
        imprimirseparador()
        if len(contraseña_servicio) >= 1:
            break
        console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]La contraseña debe tener al menos 1 caracter.[/bold bright_white]"+"\n")
        imprimirseparador()

    while True:
        clave_servicio = Prompt.ask("[bold bright_yellow]🔑[/bold bright_yellow] [bold bright_white]Clave[/bold bright_white]", password=False).strip()
        imprimirseparador()
        if len(clave_servicio) >= 1:
            break
        console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]La contraseña debe tener al menos 1 caracter.[/bold bright_white]"+"\n")
        imprimirseparador()


    # Cifrar la contraseña
    contraseña_cifrado = Fernet(derivar_clave(perfil["clave_maestra_cifrada"]))
    contraseña_cifrada = contraseña_cifrado.encrypt(contraseña_servicio.encode()).decode()
    clave_cifrado = Fernet(derivar_clave(perfil["clave_maestra_cifrada"]))
    clave_servicio = clave_cifrado.encrypt(clave_servicio.encode()).decode()

    # Agregar credencial al usuario activo
    if "credenciales" not in perfil:
        perfil["credenciales"] = []

    perfil["credenciales"].append({
        "servicio": servicio,
        "usuario": usuario_servicio,
        "correo": correo_servicio,
        "contraseña": contraseña_cifrada,
        "clave" : clave_servicio
    })

    # Guardar cambios en el JSON
    with open(USUARIOS_FILE, "w") as f:
        json.dump(usuarios, f, indent=4)

    console.print("[bold bright_green]✅[/bold bright_green] [bold bright_white]Credencial agregada exitosamente.[/bold bright_white]\n")
    imprimirseparador()
    menu_perfil(perfil_seleccionado)

# ─────────────────────────────────────────────────────────────────────────────
# 🔄 LISTAR CREDENCIALES
# ─────────────────────────────────────────────────────────────────────────────
def listar_credenciales(perfil_seleccionado):
    """Muestra todas las credenciales almacenadas en el perfil."""
    if not os.path.exists(USUARIOS_FILE):

        console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]No hay usuarios registrados aún.[/bold bright_white]"+"\n")
        imprimirseparador()
        return

    with open(USUARIOS_FILE, "r") as f:
        try:
            usuarios = json.load(f)
        except json.JSONDecodeError:

            console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]Error al cargar el archivo de usuarios.[/bold bright_white]")
            imprimirseparador()
            return

    perfil = next((u for u in usuarios if u["nombre_usuario"] == perfil_seleccionado), None)

    if not perfil or "credenciales" not in perfil or not perfil["credenciales"]:

        console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]No hay credenciales guardadas.[/bold bright_white]"+"\n")
        imprimirseparador()
        return

    contraseña_cifrado = Fernet(derivar_clave(perfil["clave_maestra_cifrada"]))
    clave_cifrado = Fernet(derivar_clave(perfil["clave_maestra_cifrada"]))
    
    console.print(Panel(f"[bold bright_Magenta]📌[/bold bright_Magenta] [bold bright_white]LISTA DE CREDENCIALES USUARIO [bold bright_yellow]{perfil_seleccionado}[/bold bright_yellow] [/bold bright_white] [bold bright_Magenta]📌[/bold bright_Magenta]"))
    print("\n")

    console.print("[bold bright_blue]➖[/bold bright_blue] [bold bright_white]A continuación, podra visualizar todas las credenciales que tiene asociadas.[/bold bright_white]"+"\n")

    tabla = Table(title=f"📌 LISTA DE CREDENCIALES USUARIO {perfil_seleccionado} 📌", show_lines=True)
    tabla.add_column("#", style="bold cyan", justify="center")
    tabla.add_column("Servicio", style="bold magenta", justify="center")
    tabla.add_column("Usuario", style="bold green", justify="center")
    tabla.add_column("Correo", style="bold blue", justify="center")
    tabla.add_column("Contraseña", style="bold yellow", justify="center")
    tabla.add_column("Clave", style="bold red", justify="center")



    credenciales_ordenadas = sorted(perfil["credenciales"], key=lambda x: x["servicio"].lower())

    for idx, cred in enumerate(credenciales_ordenadas, start=1):
        contraseña_descifrada = contraseña_cifrado.decrypt(cred["contraseña"].encode()).decode()
        clave_descifrada = clave_cifrado.decrypt(cred["clave"].encode()).decode()

        tabla.add_row(str(idx), cred["servicio"], cred["usuario"], cred["correo"], contraseña_descifrada, clave_descifrada)



    console.print(tabla)
    print("\n")
    imprimirseparador()

# ─────────────────────────────────────────────────────────────────────────────
# 🔄 ELIMINAR CREDENCIALES
# ─────────────────────────────────────────────────────────────────────────────
def eliminar_credencial(perfil_seleccionado):
    """Elimina una credencial específica del perfil."""
    if not os.path.exists(USUARIOS_FILE):
        console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]No hay usuarios registrados aún.[/bold bright_white]"+"\n")
        imprimirseparador()
        return

    with open(USUARIOS_FILE, "r") as f:
        try:
            usuarios = json.load(f)
        except json.JSONDecodeError:
            console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]Error al cargar el archivo de usuarios.[/bold bright_white]"+"\n")
            imprimirseparador()
            return

    perfil = next((u for u in usuarios if u["nombre_usuario"] == perfil_seleccionado), None)

    if not perfil or "credenciales" not in perfil or not perfil["credenciales"]:
        console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]No hay credenciales para eliminar.[/bold bright_white]"+"\n")
        imprimirseparador()
        return

    console.print(Panel(f"[bold bright_Magenta]📌[/bold bright_Magenta] [bold bright_white]ELIMINAR CREDENCIALES PARA [bold bright_yellow]{perfil_seleccionado}[/bold bright_yellow] [/bold bright_white] [bold bright_Magenta]📌[/bold bright_Magenta]"))
    print("\n")
    console.print("[bold bright_blue]➖[/bold bright_blue] [bold bright_white]Estas son todas las credenciales que tiene asociadas.[/bold bright_white]"+"\n")

    for idx, cred in enumerate(perfil["credenciales"], start=1):
        console.print(f"[{idx}] {cred['servicio']} - {cred['usuario']}")

    
    console.print("\n[0] Volver atrás\n")

    seleccion = Prompt.ask("[bold bright_white]Selecciona la credencial a eliminar[/bold bright_white]").strip()

    try:
        seleccion = int(seleccion)
        if 1 <= seleccion <= len(perfil["credenciales"]):
            perfil["credenciales"].pop(seleccion - 1)

            with open(USUARIOS_FILE, "w") as f:
                json.dump(usuarios, f, indent=4)

            imprimirseparador()
            console.print("[bold bright_green]✅[/bold bright_green] [bold bright_white]Credencial eliminada con éxito.[/bold bright_white]"+"\n")
            imprimirseparador()

        elif seleccion == "0":
            regresando()
            menu_perfil(perfil_seleccionado)


        else:
            imprimirseparador()
            console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]Opción inválida. Intenta de nuevo.[/bold bright_white]"+"\n")
            imprimirseparador()
    except ValueError:
        imprimirseparador()
        console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]Opción inválida. Intenta de nuevo.[/bold bright_white]"+"\n")
        imprimirseparador()
# ─────────────────────────────────────────────────────────────────────────────
# 🔄 CAMBIO DE CLAVE MAESTRA
# ─────────────────────────────────────────────────────────────────────────────

def cambio_clave_maestra(perfil_seleccionado):
    """Permite cambiar la clave maestra y recifrar las credenciales."""
    if not os.path.exists(USUARIOS_FILE):
        imprimirseparador()
        console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]No hay usuarios registrados aún.[/bold bright_white]")
        imprimirseparador()        
        return

    with open(USUARIOS_FILE, "r") as f:
        try:
            usuarios = json.load(f)
        except json.JSONDecodeError:
            imprimirseparador()
            console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]Error al cargar el archivo de usuarios.[/bold bright_white]")
            imprimirseparador()
            return

    perfil = next((u for u in usuarios if u["nombre_usuario"] == perfil_seleccionado), None)

    if not perfil:
        console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]Usuario no encontrado.[/bold bright_white]")
        return

    console.print("[bold bright_blue]➖[/bold bright_blue] [bold bright_white]Estás a punto de realizar el cambio de tu clave maestra. Por favor, ingresa la información que te pedimos a continuación.[/bold bright_white]\n")
    
    clave_antigua = Prompt.ask("[bold bright_yellow]🔑 Ingrese su clave maestra actual[/bold bright_yellow]", password=False).strip()

    if not verificar_clave_maestra(perfil_seleccionado, clave_antigua):
        imprimirseparador()
        console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]Clave maestra incorrecta.[/bold bright_white]\n")
        imprimirseparador()
        return

    imprimirseparador()
    console.print("[bold bright_green]✅[/bold bright_green] [bold bright_white]Clave correcta.[/bold bright_white]\n")
    imprimirseparador()

    # Captura clave maestra
    while True:
        nueva_clave = Prompt.ask("[bold bright_yellow]🔑 Ingrese su nueva clave maestra[/bold bright_yellow]", password=False).strip()
        imprimirseparador()

        # Validar clave maestra
        es_valida, mensaje = validar_clave_maestra(nueva_clave)
        if es_valida:
            break

        console.print(f"[bold bright_red]❌[/bold bright_red] [bold bright_white]{mensaje}[/bold bright_white]\n")
        imprimirseparador()

    # Confirmar clave maestra
    while True:
        clave_confirmacion = Prompt.ask("[bold bright_yellow]🔑 Repita la nueva clave maestra[/bold bright_yellow]", password=False).strip()
        imprimirseparador()

        if nueva_clave != clave_confirmacion:
            console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]Las claves no coinciden. Inténtelo de nuevo.[/bold bright_white]\n")
            imprimirseparador()
        else:
            break  # Si las claves coinciden, sale del bucle

    # Recifrar credenciales con la nueva clave
    clave_antigua_cifrada = Fernet(derivar_clave(clave_antigua))
    clave_nueva_cifrada = Fernet(derivar_clave(nueva_clave))

    for cred in perfil.get("credenciales", []):
        clave_descifrada = clave_antigua_cifrada.decrypt(cred["clave"].encode()).decode()
        cred["clave"] = clave_nueva_cifrada.encrypt(clave_descifrada.encode()).decode()

    perfil["clave_maestra_cifrada"] = cifrar_clave_maestra(nueva_clave)

    with open(USUARIOS_FILE, "w") as f:
        json.dump(usuarios, f, indent=4)


    console.print("[bold bright_green]✅[/bold bright_green] [bold bright_white]Clave maestra cambiada y credenciales actualizadas.[/bold bright_white]"+"\n")
    imprimirseparador()

# ─────────────────────────────────────────────────────────────────────────────
# 🔄 ACTUALIZAR INFORMAACIÓN
# ─────────────────────────────────────────────────────────────────────────────
def actualizar_informacion(perfil_seleccionado):
    """Permite actualizar la información del usuario (nombre o correo)."""
    if not os.path.exists(USUARIOS_FILE):
        console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]No hay usuarios registrados aún.[/bold bright_white]")
        return

    with open(USUARIOS_FILE, "r") as f:
        try:
            usuarios = json.load(f)
        except json.JSONDecodeError:
            imprimirseparador()
            console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]Error al cargar el archivo de usuarios.[/bold bright_white]"+"\n")
            imprimirseparador()
            return

    perfil = next((u for u in usuarios if u["nombre_usuario"] == perfil_seleccionado), None)

    if not perfil:
        imprimirseparador()
        console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]Usuario no encontrado.[/bold bright_white]"+"\n")
        imprimirseparador()
        return

    console.print("\n[bold bright_white]¿Qué información desea actualizar?[/bold bright_white]"+"\n")
    console.print("[1] Nombre de usuario")
    console.print("[2] Correo electrónico"+"\n")
    console.print("[0] Volver atrás"+"\n")

    opcion = Prompt.ask("[bold bright_white]Selecciona una opción[/bold bright_white]").strip()
    ingresando()

    if opcion == "1":
        while True:
            nuevo_nombre = Prompt.ask("[bold bright_yellow]✏️ Ingrese el nuevo nombre de usuario (Solo letras)[/bold bright_yellow]").strip()
            if nuevo_nombre.isalpha():
                perfil["nombre_usuario"] = nuevo_nombre
                break
            imprimirseparador()
            console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]El nombre de usuario debe contener solo [bold bright_yellow]LETRAS[/bold bright_yellow].[/bold bright_white]\n")
            imprimirseparador()
        
    elif opcion == "2":
        while True:
            nuevo_correo = Prompt.ask("[bold bright_blue]📧 Ingrese el nuevo correo electrónico[/bold bright_blue]").strip()
            if validar_correo(nuevo_correo):
                perfil["correo"] = nuevo_correo
                break
            imprimirseparador()
            console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]El correo no tiene el formato correcto [bold bright_yellow]ejemplo@ejemplo.com[/bold bright_yellow].[/bold bright_white]\n")
            imprimirseparador()

    elif opcion == "0":
        return
    else:
        imprimirseparador()
        console.print("[bold bright_red]❌[/bold bright_red] [bold bright_white]Opción inválida.[/bold bright_white]\n")
        imprimirseparador()
        return

    with open(USUARIOS_FILE, "w") as f:
        json.dump(usuarios, f, indent=4)

    imprimirseparador()
    console.print("[bold bright_green]✅[bold bright_green] [bold bright_white]Información actualizada con éxito.[/bold bright_white]\n")
    imprimirseparador()
    main()

if __name__ == "__main__":
    main()

