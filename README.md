# 🔐 Manager Password

## 📌 Description 

This project allows for secure credential management through the use of a master key and encryption of service access credentials. The system allows for easy and secure registration, listing, deletion, and updating of credentials associated with a user.

## 🚀 Characteristics  

✅ **Password and key encryption:** Access credentials are stored encrypted using the master key.
✅ **User profile management:** You can create and manage multiple user profiles.
✅ **Credential re-encryption:** When you change the master key, all credentials are updated with the new key.
✅ **Simple user interface:** Interactive interface for managing credentials through the console.

## 🛠️ Technologies Used
- Python
  
## 📝 Requirements

- Python 3.x
- Dependencies:
  - `cryptography`
  - `rich`
  - `prompt_toolkit`
  - `json`

## 📥 Installation and Use 

To install the necessary dependencies, you can use `pip`:

```bash
pip install cryptography rich prompt_toolkit
```
## Usage
Create a new profile
1. Run the program:
```bash
python main.py
```
2. Select the option to create a new profile and provide the required information (username and master key).

## Manage credentials
Once the profile is created, you can perform the following actions:

- List credentials: View all credentials associated with a profile.
- Delete credential: Remove a specific credential from the selected profile.
- Update profile information: Change the username or email address.
- Change master key: Change the master key that encrypts stored credentials. This will update all associated credentials.

## Workflow example
Log in with your profile.

- List your credentials to view services, users, email addresses, and passwords.
- If you want to delete a credential, select the appropriate option and confirm the deletion.
- If you decide to update your master password, enter your current password, then the new password, and repeat it to confirm.
- If you need to update your profile information, you can change your username or email address.

## 🛡️ Seguridad

- Symmetric encryption: The system uses Fernet from the cryptography library to encrypt and decrypt passwords and keys, ensuring the protection of stored credentials.
- Master key: The master key is the primary access point to all credentials. It is crucial that the master key be kept secret and chosen securely.

## 📝 Contributions

If you'd like to improve this project, any contribution is welcome!

1. Fork the repository.
2. Create a new branch:
```bash
   git checkout -b mi-nueva-funcionalidad
```
3. Make your improvements and commit:
```bash
   git commit -m "Agregada nueva funcionalidad"
```
4.Upgrade the gears:
```bash
  git push origin mi-nueva-funcionalidad
```
5. Create a pull request explaining your changes.
