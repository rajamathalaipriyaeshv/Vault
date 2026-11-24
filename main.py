import os
import base64
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

SALT_FILENAME = "encryption_salt.meta"

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a secure 32-byte key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_folder(target_folder: str, password: str):
    """Encrypts all files in a folder and saves a salt for future decryption."""
    # 1. Generate a new, secure random salt
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)

    # 2. Save the salt in the target folder so we can use it to decrypt later
    salt_path = os.path.join(target_folder, SALT_FILENAME)
    with open(salt_path, "wb") as salt_file:
        salt_file.write(salt)

    # 3. Walk through the directory tree
    for root, dirs, files in os.walk(target_folder):
        for file in files:
            # Skip the salt file and already encrypted files
            if file == SALT_FILENAME or file.endswith(".enc"):
                continue

            file_path = os.path.join(root, file)
            enc_file_path = file_path + ".enc"

            try:
                # Read, encrypt, and write to a new .enc file
                with open(file_path, "rb") as original_file:
                    original_data = original_file.read()

                encrypted_data = f.encrypt(original_data)

                with open(enc_file_path, "wb") as encrypted_file:
                    encrypted_file.write(encrypted_data)

                # Delete the original unencrypted file
                os.remove(file_path)
                print(f"🔒 Encrypted: {file}")

            except Exception as e:
                print(f"⚠️ Error encrypting {file}: {e}")

    print("\n✅ Folder encryption complete!")

def decrypt_folder(target_folder: str, password: str):
    """Reads the folder's salt, derives the key, and decrypts all .enc files."""
    salt_path = os.path.join(target_folder, SALT_FILENAME)

    if not os.path.exists(salt_path):
        print("❌ Error: Salt file not found. Cannot derive the key to decrypt.")
        return

    # 1. Read the salt and generate the exact same key
    with open(salt_path, "rb") as salt_file:
        salt = salt_file.read()
 
    key = derive_key(password, salt)
    f = Fernet(key)

    # 2. Walk through the directory tree
    for root, dirs, files in os.walk(target_folder):
        for file in files:
            # Only attempt to decrypt .enc files
            if file.endswith(".enc"):
                file_path = os.path.join(root, file)
                # Remove the '.enc' to get the original filename back
                original_file_path = file_path[:-4] 

                try:
                    # Read, decrypt, and restore original file
                    with open(file_path, "rb") as encrypted_file:
                        encrypted_data = encrypted_file.read()

                    decrypted_data = f.decrypt(encrypted_data)

                    with open(original_file_path, "wb") as original_file:
                        original_file.write(decrypted_data)

                    # Delete the .enc file
                    os.remove(file_path)
                    print(f"🔓 Decrypted: {file}")

                except InvalidToken:
                    print(f"❌ Decryption failed for {file}. Wrong password!")
                    return # Stop trying if the password is wrong
                except Exception as e:
                    print(f"⚠️ Error decrypting {file}: {e}")
                    
    # Clean up the salt file after successful decryption
    if os.path.exists(salt_path):
        os.remove(salt_path)
        
    print("\n✅ Folder decryption complete!")

# ==========================================
# COMMAND LINE INTERFACE
# ==========================================
if __name__ == "__main__":
    print("=== Folder Encryptor Engine ===")
    folder_to_process = input("Enter the path to your dummy folder: ").strip()
    
    # Strip quotes just in case you drag-and-dropped the folder into the terminal
    folder_to_process = folder_to_process.strip('"').strip("'")
    
    if not os.path.isdir(folder_to_process):
        print("❌ Error: That folder does not exist.")
    else:
        action = input("Type 'E' to Encrypt or 'D' to Decrypt: ").strip().upper()
        
        # getpass hides your keystrokes for security
        user_pwd = getpass("Enter your password: ")
        
        if action == 'E':
            encrypt_folder(folder_to_process, user_pwd)
        elif action == 'D':
            decrypt_folder(folder_to_process, user_pwd)
        else:
            print("Invalid choice. Exiting.")