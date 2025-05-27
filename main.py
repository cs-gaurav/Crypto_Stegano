import base64
import os
import numpy as np
from PIL import Image
from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
output_folder = os.path.join(app.root_path, 'static', 'temp')
os.makedirs(output_folder, exist_ok=True)

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



### ---------- ENCRYPT & HIDE ----------
def encrypt_message(message: str, password: str):
    salt = os.urandom(16)
    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(message.encode())
    return salt + encrypted  # prepend salt to encrypted data



def hide_data_in_image(image, output_path, data_bytes):
    bit_string = to_bitstring(data_bytes)
    data_len = len(bit_string)

    img = image.convert('RGB')
    pixels = np.array(img)
    flat_pixels = pixels.flatten()

    if data_len > len(flat_pixels):
        raise ValueError("Data is too large to hide in this image.")

    for i in range(data_len):
        flat_pixels[i] = (flat_pixels[i] & 0xFE) | int(bit_string[i])

    new_pixels = flat_pixels.reshape(pixels.shape)
    new_img = Image.fromarray(new_pixels.astype('uint8'), 'RGB')
    new_img.save(output_path)



### ---------- EXTRACT & DECRYPT ----------
def extract_bits_from_image(image_path, num_bits):
    img = Image.open(image_path).convert('RGB')
    pixels = np.array(img).flatten()
    return ''.join([str(pixels[i] & 1) for i in range(num_bits)])

def decrypt_data(encrypted: bytes, password: str, salt: bytes):
    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted).decode()




@app.route("/")
def home():
    return render_template("home.html")



@app.route("/encrypt", methods=["GET", "POST"])
def encryption_method():
    if request.method == "POST":
        message = request.form.get("user_message")
        password = request.form.get("user_key")
        image_file = request.files.get("user_image")

        if not message or not password or not image_file:
            return render_template("encrypt.html", error="All fields are required!")

        try:
            img = Image.open(image_file.stream)
            combined_data = encrypt_message(message, password)

            output_filename = "stego_image.png"
            output_path = os.path.join(output_folder, output_filename)

            hide_data_in_image(img, output_path, combined_data)

            bits_hidden = len(combined_data) * 8

            # Show bits_hidden and provide download link
            return render_template(
                "encrypt.html",
                bits_hidden=bits_hidden,
                download_file=output_filename,
                success=True
            )
        
        except Exception as e:
            return render_template("encrypt.html", error=f"Error: {str(e)}")

    return render_template("encrypt.html")



@app.route('/download/<filename>')
def download_file(filename):
    print(f"Download requested for file: {filename}")
    file_path = os.path.join(output_folder, filename)
    return send_file(file_path, as_attachment=True)



@app.route("/decrypt", methods=["GET", "POST"])
def decryption_method():
    if request.method == "POST":
        password = request.form.get("user_key")
        image_file = request.files.get("user_image")

        if not password or not image_file:
            return render_template("decrypt.html", error="Both fields are required!")

        try:
            filename = secure_filename(image_file.filename)
            download_folder = os.path.expanduser("~/Downloads")
            temp_path = os.path.join(download_folder, filename)
            image_file.save(temp_path)

            img = Image.open(temp_path).convert('RGB')
            pixels = np.array(img).flatten()

            # We need to extract the salt length + encrypted data length in bits.
            total_bits = int(request.form.get("total_bits"))
            bit_string = extract_bits_from_image(temp_path, total_bits)
            hidden_bytes = bitstring_to_bytes(bit_string)

            # Salt is first 16 bytes
            salt = hidden_bytes[:16]

            # Encrypted data follows salt
            encrypted_data = hidden_bytes[16:]

            # Try decrypting with password
            fernet_key = derive_key_from_password(password, salt)
            fernet = Fernet(fernet_key)

            try:
                decrypted_message = fernet.decrypt(encrypted_data).decode()
            except Exception:
                return render_template("decrypt.html", error="Incorrect password or corrupted data.")

            return render_template("decrypt.html", message=decrypted_message)

        except Exception as e:
            return render_template("decrypt.html", error=f"Error: {str(e)}")

    return render_template("decrypt.html")

if __name__ == "__main__":
    app.run(debug=True)
