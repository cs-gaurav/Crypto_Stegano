# Stegano_Crypto
Cyber PBL Project

Project Overview:

In this project, we developed a secure data-hiding tool using a combination of cryptography and steganography. The main goal was to protect sensitive information by encrypting it and then hiding it inside an image. We used Fernet symmetric encryption to ensure that only users with the correct password can access the message. Once encrypted, the data is embedded into the image using Least Significant Bit (LSB) steganography, which makes subtle pixel changes that are visually undetectable.

Implementation:

The entire system was built using Python, and a basic HTML/CSS interface was created to make the tool easier to use. We handled all core functionalities including encryption, bitstream conversion, image capacity validation, data embedding, and secure extraction with decryption. The password-based encryption system uses a salt and PBKDF2 key derivation to prevent mismatches and strengthen security.


Challenges and Solutions:

During development, we faced some technical issues. One major challenge was inconsistent decryption due to mismatched keys, which we solved by attaching a salt during encryption. Another issue was image overwriting during testing, which we avoided by saving output as new files. We also added pre-validation checks to ensure the image was large enough to hold the hidden message. Initially, the tool was CLI-based, so we improved user experience by adding a basic GUI with helpful prompts and messages.


Future Improvements:

In the future, we plan to:
* Develop a more advanced GUI for easier interaction.
* Add support for embedding data in audio and video files.
* Implement better error handling for unsupported or corrupted image files.
These enhancements will make the tool more versatile, user-friendly, and reliable across various use cases.


Final Outcome: 

The final result is a fully functional tool capable of securely encrypting, embedding, extracting, and decrypting hidden messages in images. All major functionalities have been tested and documented. The tool performs well, maintains image quality, and ensures that only authorized users can retrieve the hidden data. Full documentation, sample test cases, and usage instructions are also included with the project.

