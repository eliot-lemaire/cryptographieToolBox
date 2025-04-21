import os
import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
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

buttonHashCalculate = tk.Button(root, text="Make a key.", command=generate_key)
buttonHashCalculate.pack(pady=20)

buttonHashCalculate = tk.Button(root, text="Encrypte a file", command=encrypt_file)
buttonHashCalculate.pack(pady=20)

root.mainloop() # Keeps the window open and waits for input