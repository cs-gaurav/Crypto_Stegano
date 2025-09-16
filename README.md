# Stegano_Crypto
Cyber PBL Project

- Project Overview:

In this project, we developed a secure data-hiding tool using a combination of cryptography and steganography. The main goal was to protect sensitive information by encrypting it and then hiding it inside an image. We used Fernet symmetric encryption to ensure that only users with the correct password can access the message. Once encrypted, the data is embedded into the image using Least Significant Bit (LSB) steganography, which makes subtle pixel changes that are visually undetectable.

- How It Works:

- Encryption and Hiding

    Input: The user provides a message, a password, and a cover image.

    Key Derivation: A cryptographic key is generated from the user's password using the PBKDF2HMAC algorithm with SHA256 hashing and a salt. This adds a layer of protection against brute-force attacks.

    Encryption: The message is encrypted using the derived key and the Fernet symmetric encryption scheme, which ensures that the message can only be decrypted with the correct key. The salt is prepended to the encrypted data.

    Steganography: The encrypted data (including the salt) is converted into a binary string. The bits of this string are then hidden within the least significant bit of each pixel's color value in the image. For example, if a pixel's red value is 10101010, the last 0 would be replaced with the next bit from the binary string.

    Output: The resulting stego image is provided for download. The total number of bits hidden is also displayed, which is required for later decryption.

- Extraction and Decryption

    Input: The user uploads the stego image and provides the password and the total number of hidden bits.

    Extraction: The program extracts the specified number of LSBs from the image's pixel data to retrieve the hidden binary string.

    Data Separation: The first 16 bytes of the extracted data are identified as the salt, and the remaining bytes are the encrypted message.

    Key Derivation: The same PBKDF2HMAC process is used with the provided password and the extracted salt to regenerate the correct cryptographic key.

    Decryption: The encrypted message is decrypted using the regenerated key and the Fernet scheme.

    Output: The original, hidden message is displayed to the user. An error is shown if the password is incorrect or the data is corrupted.

- Technologies Used:

    Python: The core programming language for the back-end logic.

    Flask: A micro web framework used to create the web application's routes and handle HTTP requests.

    Pillow (PIL): A library for opening, manipulating, and saving many different image file formats.

    NumPy: A library for working with arrays, used here to efficiently manipulate the pixel data of the images.

    Cryptography.io: A Python library that provides cryptographic recipes and primitives for implementing secure encryption. Specifically, it uses PBKDF2HMAC for key derivation and Fernet for symmetric encryption.

    HTML & CSS: Used for creating a user-friendly and visually appealing web interface.

    JavaScript: Used for minor front-end functionality, such as displaying a download popup.

- Project Structure:

    main.py: Contains the Flask application logic, including the routes for home, encryption, and decryption, as well as the core steganography and cryptography functions.

    templates/: Directory for HTML files.

        home.html: The landing page with links to the encryption and decryption sections.

        encrypt.html: The user interface for encrypting and hiding a message.

        decrypt.html: The user interface for decrypting and extracting a message.

    static/: Directory for static files like CSS and images.

        style.css: Defines the styling for all web pages.

        temp/: A temporary folder where the generated stego images are saved before being downloaded.


- Challenges and Solutions:

During development, we faced some technical issues. One major challenge was inconsistent decryption due to mismatched keys, which we solved by attaching a salt during encryption. Another issue was image overwriting during testing, which we avoided by saving output as new files. We also added pre-validation checks to ensure the image was large enough to hold the hidden message. Initially, the tool was CLI-based, so we improved user experience by adding a basic GUI with helpful prompts and messages.


- Future Improvements:

In the future, we plan to:
* Develop a more advanced GUI for easier interaction.
* Add support for embedding data in audio and video files.
* Implement better error handling for unsupported or corrupted image files.
These enhancements will make the tool more versatile, user-friendly, and reliable across various use cases.


- Final Outcome: 

The final result is a fully functional tool capable of securely encrypting, embedding, extracting, and decrypting hidden messages in images. All major functionalities have been tested and documented. The tool performs well, maintains image quality, and ensures that only authorized users can retrieve the hidden data. Full documentation, sample test cases, and usage instructions are also included with the project.

