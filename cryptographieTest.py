from cryptography.fernet import Fernet

key = Fernet.generate_key()

# Save the key to a file
with open("secret.key", "wb") as key_file:
    key_file.write(key)

# Load the key from the file
with open("secret.key", "rb") as key_file:
    loaded_key = key_file.read()

# Create a Fernet object with the loaded key
f = Fernet(loaded_key)

# Now you can encrypt and decrypt with this loaded key
message = b"Here's another secret message!"
encrypted_message = f.encrypt(message)
decrypted_message = f.decrypt(encrypted_message)

print("Encrypted message:", encrypted_message)
print("Decrypted message:", decrypted_message)

