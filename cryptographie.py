import os
import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa   # libary to work with rsa keys
from cryptography.hazmat.primitives import serialization    # libary to load and save .pem keys
from cryptography.fernet import Fernet
import rsa

root = tk.Tk() # Creates a window
root.title("cryptographie tool kit") 
root.geometry("300x700")    # set window size

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
    public_key, private_key = rsa.newkeys(1024)

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
            f.write(private_key.save_pkcs1("PEM"))

        # Save public key to file
        with open(store_public_key, "wb") as f:
            f.write(public_key.save_pkcs1("PEM"))

def asymmetric_encryption():
    file_path = filedialog.askopenfilename()
    public_key_path = filedialog.askopenfilename()

    with open(public_key_path, "rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())

    with open(file_path, 'rb') as file:
    # Read the content of the file
        content = file.read()

    encrypted_message = rsa.encrypt(content, public_key)

    with open(file_path + ".encrypted", "wb") as f :
        f.write(encrypted_message)

    os.remove(file_path)

def asymmetric_decryption():
    file_path = filedialog.askopenfilename()
    private_key_path = filedialog.askopenfilename()

    with open(private_key_path, "rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())

    encrypted_message = open(file_path, "rb").read()

    clear_message = rsa.decrypt(encrypted_message, private_key)

    base, ext = os.path.splitext(file_path)  # ext = '.encrypted'
    decrypted_path = base  # 'example.txt'

    with open(decrypted_path, "wb") as f :
        f.write(clear_message)

    os.remove(file_path)

def sign_file():
    file_path = filedialog.askopenfilename()
    private_key_path = filedialog.askopenfilename()

    with open(private_key_path, "rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())

    with open(file_path, 'rb') as file:
    # Read the content of the file
        data = file.read()

    signature = rsa.sign(data, private_key, "SHA-256")

    with open(file_path + ".sig", "wb") as f :
        f.write(signature)



def sign_file_verify():
    original_file_path = filedialog.askopenfilename()
    signature_file_path = filedialog.askopenfilename()
    public_key_path = filedialog.askopenfilename()

    with open(public_key_path, "rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())

    with open(signature_file_path, "rb") as f:
        signature = f.read()

    with open(original_file_path, "rb") as f:
        message = f.read()

    try:
        result = rsa.verify(message, signature, public_key)
        print(result)
        messagebox.showinfo(f"info", f"proof of origin verified")
    except Exception as e:
        # something happens if there is an error
        messagebox.showinfo(f"info", f"Could not verify proof or origin")


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

buttonAsymmetricEncrypte = tk.Button(root, text="Encrypte file using public key", command=asymmetric_encryption)
buttonAsymmetricEncrypte.pack(pady=20)

buttonAsymmetricDecrypte = tk.Button(root, text="Decrypte file using private key", command=asymmetric_decryption)
buttonAsymmetricDecrypte.pack(pady=20)

labelTitle = tk.Label(root, text="Proof of Origin")
labelTitle.pack(pady=10)

buttonSign = tk.Button(root, text="Sign File", command=sign_file)
buttonSign.pack(pady=20)

buttonSignVerify = tk.Button(root, text="Verify a Signed File", command=sign_file_verify)
buttonSignVerify.pack(pady=20)

root.mainloop() # Keeps the window open and waits for inpur