
import base64
import os
import numpy as np
from PIL import Image
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hashlib
import sys

### ---------- UTILS ----------
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def to_bitstring(data: bytes) -> str:
    return ''.join(f'{byte:08b}' for byte in data)

def bitstring_to_bytes(bit_string):
    bytes_list = [bit_string[i:i+8] for i in range(0, len(bit_string), 8)]
    return bytes([int(b, 2) for b in bytes_list])

def calculate_image_hash(image_path):
    with open(image_path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

### ---------- ENCRYPT & HIDE ----------
def encrypt_message(message: str, password: str):
    salt = os.urandom(16)
    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(message.encode())
    return salt + encrypted

def hide_data_in_image(image_path, output_path, data_bytes):
    bit_string = to_bitstring(data_bytes)
    data_len = len(bit_string)

    img = Image.open(image_path)
    img = img.convert('RGB')
    pixels = np.array(img)
    flat_pixels = pixels.flatten()

    if data_len > len(flat_pixels):
        raise ValueError("Data is too large to hide in this image.")

    for i in range(data_len):
        flat_pixels[i] = (flat_pixels[i] & ~1) | int(bit_string[i])

    new_pixels = flat_pixels.reshape(pixels.shape)
    new_img = Image.fromarray(new_pixels.astype('uint8'), 'RGB')
    new_img.save(output_path)
    print(f"Encrypted data hidden in '{output_path}'.")

    # Save hash
    new_hash = calculate_image_hash(output_path)
    with open(output_path + ".hash", "w") as f:
        f.write(new_hash)
    print(f"Image SHA256 hash: {new_hash}")
    print(f"Hash saved to '{output_path}.hash'.")

### ---------- EXTRACT & DECRYPT ----------
def extract_bits_from_image(image_path, num_bits):
    img = Image.open(image_path)
    img = img.convert('RGB')
    pixels = np.array(img).flatten()
    return ''.join([str(pixels[i] & 1) for i in range(num_bits)])

def decrypt_data(encrypted: bytes, password: str, salt: bytes):
    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted).decode()

def extract_and_decrypt(image_path, total_bits, salt_len=16):
    current_hash = calculate_image_hash(image_path)
    print(f"[i] Current image hash:   {current_hash}")

    try:
        with open(image_path + ".hash", "r") as f:
            expected_hash = f.read().strip()
        print(f"[i] Loaded expected hash from {image_path}.hash")
    except FileNotFoundError:
        print("Hash file not found! Integrity check failed. Aborting.")
        sys.exit(1)

    if current_hash != expected_hash:
        print("WARNING: Image has been tampered with or altered!")
        print("Program aborted to prevent decryption of corrupted data.")
        sys.exit(1)
    else:
        print("Image integrity verified. No tampering detected.")

    bit_string = extract_bits_from_image(image_path, total_bits)
    hidden_data = bitstring_to_bytes(bit_string)

    salt = hidden_data[:salt_len]
    encrypted = hidden_data[salt_len:]

    while True:
        password = input("Enter password to decrypt: ")
        try:
            message = decrypt_data(encrypted, password, salt)
            print(f"Decrypted Message: {message}")
            break
        except Exception:
            print("Incorrect password or corrupted data. Try again.")

### ---------- TAMPER IMAGE ----------
def tamper_image(image_path, output_path):
    img = Image.open(image_path).convert('RGB')
    pixels = np.array(img)

    x, y = 0, 0
    r, g, b = pixels[y, x]
    pixels[y, x] = (r, g, (b + 1) % 256)

    tampered_img = Image.fromarray(pixels, 'RGB')
    tampered_img.save(output_path)
    print(f"[!] Image tampered and saved as '{output_path}'")

### ---------- MAIN ----------
def main():
    print("1. Encrypt and Hide\n2. Extract and Decrypt\n3. Tamper Image")
    choice = input("Select (1/2/3): ")

    if choice == '1':
        input_image = input("Enter input image path (e.g., original.png): ")
        output_image = input("Enter output image path (e.g., encoded.png): ")
        message = input("Enter the message to encrypt and hide: ")
        password = input("Enter password: ")

        combined_data = encrypt_message(message, password)
        hide_data_in_image(input_image, output_image, combined_data)
        print(f"[i] Total bits hidden: {len(combined_data) * 8}")

    elif choice == '2':
        encoded_image = input("Enter image path with hidden data: ")
        total_bits = int(input("Enter total number of bits hidden: "))
        extract_and_decrypt(encoded_image, total_bits)

    elif choice == '3':
        image_path = input("Enter path of image to tamper (e.g., encoded.png): ")
        output_path = input("Enter output image path (e.g., tampered.png): ")
        tamper_image(image_path, output_path)

    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()
