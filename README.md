# Gestión de Credenciales Seguras

Este proyecto permite gestionar credenciales de manera segura mediante el uso de una clave maestra y cifrado de las credenciales de acceso a servicios. El sistema permite registrar, listar, eliminar y actualizar las credenciales asociadas a un usuario de forma fácil y segura.

## Características

- **Cifrado de contraseñas y claves:** Las credenciales de acceso se almacenan cifradas utilizando la clave maestra.
- **Gestión de perfiles de usuario:** Puedes crear y gestionar múltiples perfiles de usuario.
- **Recifrado de credenciales:** Al cambiar la clave maestra, todas las credenciales se actualizan con la nueva clave.
- **Interfaz de usuario sencilla:** Interfaz interactiva para gestionar las credenciales a través de la consola.

## Requisitos

- Python 3.x
- Dependencias:
  - `cryptography`
  - `rich`
  - `prompt_toolkit`
  - `json`

## Instalación

Para instalar las dependencias necesarias, puedes usar `pip`:

```bash
pip install cryptography rich prompt_toolkit
```
## Uso
Crear un nuevo perfil
1. Ejecuta el programa:
  ```bash
python main.py
``` 
2. Selecciona la opción para crear un nuevo perfil y proporciona los datos requeridos (nombre de usuario y clave maestra).

## Gestionar credenciales
Una vez creado el perfil, puedes realizar las siguientes acciones:

- Listar credenciales: Ver todas las credenciales asociadas a un perfil.
- Eliminar credencial: Eliminar una credencial específica del perfil seleccionado.
- Actualizar información del perfil: Cambiar el nombre de usuario o correo electrónico.
- Cambiar clave maestra: Cambiar la clave maestra que cifra las credenciales almacenadas. Esto actualizará todas las credenciales asociadas.

## Ejemplo de flujo de trabajo
Iniciar sesión con tu perfil.

- Listar tus credenciales para visualizar los servicios, usuarios, correos y contraseñas.
- Si deseas eliminar una credencial, selecciona la opción adecuada y confirma la eliminación.
- Si decides actualizar tu clave maestra, ingresa tu clave actual, luego la nueva clave y repítela para confirmarla.
- Si necesitas actualizar la información del perfil, puedes modificar tu nombre de usuario o correo electrónico.

## Seguridad

- Cifrado simétrico: El sistema utiliza Fernet de la librería cryptography para cifrar y descifrar las contraseñas y claves, asegurando la protección de las credenciales almacenadas.
- Clave maestra: La clave maestra es el punto de acceso principal a todas las credenciales. Es crucial que la clave maestra se mantenga en secreto y se elija de manera segura.

### Contribuciones
Si deseas contribuir a este proyecto, por favor sigue los siguientes pasos:

- Haz un fork del repositorio.
- Crea una rama (git checkout -b feature-nueva).
- Realiza tus cambios y haz commit (git commit -am 'Agregando nueva funcionalidad').
- Haz push a la rama (git push origin feature-nueva).
- Crea un pull request.
