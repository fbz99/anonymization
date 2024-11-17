import json
import os
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pathlib import Path


# RSA Key Management
def load_private_key():
    """
    Load RSA private key from the private_key.pem file.
    """
    with open("private_key.pem", "rb") as private_file:
        private_key = serialization.load_pem_private_key(
            private_file.read(),
            password=None,
        )
    return private_key


# Hybrid Decryption Function
def hybrid_decrypt(encrypted_package, private_key):
    """
    Decrypt data using hybrid AES + RSA decryption.
    """
    encrypted_aes_key = base64.b64decode(encrypted_package["encrypted_aes_key"])
    iv = base64.b64decode(encrypted_package["iv"])
    encrypted_data = base64.b64decode(encrypted_package["encrypted_data"])

    # Decrypt AES key with RSA
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Decrypt data with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    return json.loads(decrypted_data.decode())


# Reconstruct Original Text
def reconstruct_text(anonymized_text, entity_mapping):
    """
    Replace placeholders in the anonymized text with the original entities.
    """
    for placeholder, original in entity_mapping:
        anonymized_text = anonymized_text.replace(placeholder, original)
    return anonymized_text


# Process Output Files
def process_output_files(output_folder, reconstructed_folder):
    """
    Process all files in the output folder, decrypt mappings, and reconstruct original texts.
    """
    os.makedirs(reconstructed_folder, exist_ok=True)
    private_key = load_private_key()

    for file_path in Path(output_folder).rglob("*.json"):
        try:
            # Load anonymized file
            with open(file_path, "r", encoding="utf-8") as file:
                data = json.load(file)

            anonymized_text = data["anonymized_text"]
            encrypted_mapping = data["encrypted_mapping"]

            # Decrypt entity mapping
            entity_mapping = hybrid_decrypt(encrypted_mapping, private_key)

            # Reconstruct the original text
            reconstructed_text = reconstruct_text(anonymized_text, entity_mapping)

            # Save reconstructed text to the reconstructed folder
            base_filename = Path(file_path).stem.replace("_processed", "_reconstructed")
            output_file = Path(reconstructed_folder) / f"{base_filename}.txt"
            with open(output_file, "w", encoding="utf-8") as output:
                output.write(reconstructed_text)

            print(f"Reconstructed text saved to {output_file}")
        except Exception as e:
            print(f"Error processing {file_path}: {e}")


if __name__ == "__main__":
    # Static folders
    output_folder = "output"
    reconstructed_folder = "reconstructed"

    # Process files
    process_output_files(output_folder, reconstructed_folder)
