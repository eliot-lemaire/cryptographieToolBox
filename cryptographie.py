import os
import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa   # libary to work with rsa keys
from cryptography.hazmat.primitives import serialization    # libary to load and save .pem keys
from cryptography.fernet import Fernet

root = tk.Tk() # Creates a window
root.title("cryptographie tool kit") 
root.geometry("300x150")    # set window size

def generate_key():

    key = Fernet.generate_key()

    file_path = filedialog.asksaveasfilename(
    defaultextension=".key",  # Default file extension
    filetypes=[("key files", "*.key"), ("All files", "*.*")],  # Allowed file types
    title="Save your file as"
)

# Check if the user selected a file path (not canceled)
    if file_path:
        with open(file_path, 'wb') as file:
            file.write(key)

def encrypt_file():
    file_path = filedialog.askopenfilename()
    key_path = filedialog.askopenfilename()

    with open(key_path, "rb") as key_file:
        loaded_key = key_file.read()

    # Create a Fernet object with the loaded key
    f = Fernet(loaded_key)

    # Encrypt a file
    with open(file_path, "rb") as file:  # Replace with your file path
        original_data = file.read()

    encrypted_data = f.encrypt(original_data)

    with open(file_path + ".encrypted", "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)

    os.remove(file_path)

def decrypte_file():
    file_path = filedialog.askopenfilename()
    key_path = filedialog.askopenfilename()

    with open(key_path, "rb") as key_file:
        loaded_key = key_file.read()

    # Create a Fernet object with the loaded key
    f = Fernet(loaded_key)

    # decrypt a file
    with open(file_path, "rb") as file:  # Replace with your file path
        original_data = file.read()

    decrypte_data = f.decrypt(original_data)

    base, ext = os.path.splitext(file_path)  # ext = '.encrypted'
    decrypted_path = base  # 'example.txt'

    with open(decrypted_path, "wb") as decrypted_file:
        decrypted_file.write(decrypte_data)

    os.remove(file_path)

def make_asimmetric_keys():
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # 2048 bits long
)

    # Get public key from private key
    public_key = private_key.public_key()   # extracts the public key from private

    store_public_key = filedialog.asksaveasfilename(
    defaultextension=".pem",  # Default file extension
    filetypes=[("key files", "*.pem"), ("All files", "*.*")],  # Allowed file types
    title="public key"
    )

    store_private = filedialog.asksaveasfilename(
    defaultextension=".pem",  # Default file extension
    filetypes=[("key files", "*.pem"), ("All files", "*.*")],  # Allowed file types
    title="private key"
    )

    if store_private:
        with open(store_private, "wb") as f:
            f.write(private_key.private_bytes(  # write private key but first make it into private bytes
                encoding=serialization.Encoding.PEM,    # format the key with PEM (Privacy-Enhanced Mail)
                format=serialization.PrivateFormat.PKCS8,   # format for storing the key, this is the most common
                encryption_algorithm=serialization.NoEncryption()   # we are not using a password to protect the key
            ))

        # Save public key to file
        with open(store_public_key, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

def asymmetric_encryption():
    file_path = filedialog.askopenfilename()
    key_path = filedialog.askopenfilename()

    with open(key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    symmetric_key = Fernet.generate_key()
    fernet = Fernet(symmetric_key)

    with open(file_path, "rb") as f:
        data = f.read()

    encrypted_data = fernet.encrypt(data)

    # Encrypt the Fernet key with the RSA public key
    encrypted_key = public_key.encrypt(
    symmetric_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )

    # Save both to files
    with open("encrypted_data.bin", "wb") as f:
        f.write(encrypted_data)

    with open("encrypted_key.bin", "wb") as f:
        f.write(encrypted_key)

def asymmetric_decryption():
    file_path = filedialog.askopenfilename()
    key_path = filedialog.askopenfilename()

labelTitle = tk.Label(root, text="Symmetric Encryption")
labelTitle.pack(pady=10)

buttonGenerateKey = tk.Button(root, text="Make a key", command=generate_key)
buttonGenerateKey.pack(pady=20)

buttonEncrypteFile = tk.Button(root, text="Encrypte a file", command=encrypt_file)
buttonEncrypteFile.pack(pady=20)

buttonDecrypteFile = tk.Button(root, text="Decrypte a file", command=decrypte_file)
buttonDecrypteFile.pack(pady=20)

labelTitle = tk.Label(root, text="Asymmetric Encryption")
labelTitle.pack(pady=10)

buttonAssymetricKeys = tk.Button(root, text="Make public and private keys", command=make_asimmetric_keys)
buttonAssymetricKeys.pack(pady=20)

buttonAssymetricEncrypte = tk.Button(root, text="Encrypte using public key", command=asymmetric_encryption)
buttonAssymetricEncrypte.pack(pady=20)

buttonAssymetricDecrypte = tk.Button(root, text="Decrypte using private key", command=make_asimmetric_keys)
buttonAssymetricDecrypte.pack(pady=20)

root.mainloop() # Keeps the window open and waits for inpur

# THINGS TO ADD
# ASYMMETRIC ENCRYPTION
# encrypt

# ASYMMETRIC DECRYPTION
# decrypte
