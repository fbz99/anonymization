import json
import os
import base64
from pathlib import Path
from gliner import GLiNER
from langdetect import detect, DetectorFactory
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom

# Ensure consistent language detection results
DetectorFactory.seed = 0


# Hybrid Encryption Functions
def hybrid_encrypt(data, public_keys_folder):
    """
    Encrypt data using hybrid AES + RSA encryption for all public keys in the folder.
    """
    aes_key = urandom(32)  # 256-bit AES key
    iv = urandom(16)  # Initialization vector for AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()

    encrypted_aes_keys = {}

    # Encrypt AES key with all available public keys
    for public_key_file in Path(public_keys_folder).rglob("*.pem"):
        with open(public_key_file, "rb") as file:
            public_key = serialization.load_pem_public_key(file.read())
            encrypted_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            encrypted_aes_keys[public_key_file.stem] = base64.b64encode(encrypted_aes_key).decode()

    return {
        "encrypted_aes_keys": encrypted_aes_keys,
        "iv": base64.b64encode(iv).decode(),
        "encrypted_data": base64.b64encode(encrypted_data).decode(),
    }



# GLiNER Model Initialization
model = GLiNER.from_pretrained("urchade/gliner_mediumv2.1")


def anonymize_text(text, labels):
    """
    Anonymize text using GLiNER for entity recognition.
    """
    entities = model.predict_entities(text, labels, threshold=0.5)
    entity_mapping = []
    anonymized_text = text

    for i, entity in enumerate(entities):
        placeholder = f"{{{{{entity['label']}_{i}}}}}"
        anonymized_text = anonymized_text.replace(entity["text"], placeholder)
        entity_mapping.append((placeholder, entity["text"]))

    return anonymized_text, entity_mapping


def process_files(input_folder, output_folder, public_keys_folder, entity_file):
    """
    Process files in the input folder, anonymize using GLiNER, and encrypt using public keys.
    """
    os.makedirs(output_folder, exist_ok=True)

    # Load entity types to recognize
    with open(entity_file, "r", encoding="utf-8") as file:
        labels = [line.strip() for line in file if line.strip()]
    print(f"Loaded entity labels: {labels}")

    for file_path in Path(input_folder).rglob("*.txt"):
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                text = file.read()

            print(f"Processing {file_path}...")

            # Detect language (optional, assumes GLiNER is language-agnostic)
            lang = detect(text)
            if lang not in ["en", "it"]:
                print(f"Skipping {file_path}: Unsupported language detected.")
                continue

            # Anonymize text
            anonymized_text, entity_mapping = anonymize_text(text, labels)

            # Encrypt entity mapping for all public keys
            encrypted_mapping = hybrid_encrypt(json.dumps(entity_mapping, ensure_ascii=False), public_keys_folder)

            # Save anonymized text and encrypted mapping
            base_filename = Path(file_path).stem
            output_file = Path(output_folder) / f"{base_filename}_processed.json"
            with open(output_file, "w", encoding="utf-8") as file:
                json.dump(
                    {"anonymized_text": anonymized_text, "encrypted_mapping": encrypted_mapping},
                    file,
                    indent=4,
                    ensure_ascii=False,
                )

            print(f"Processed {file_path} saved to {output_file}.")
        except Exception as e:
            print(f"Error processing {file_path}: {e}")


if __name__ == "__main__":
    # Static folder paths
    input_folder = "input"
    output_folder = "output"
    public_keys_folder = "public_keys"
    entity_file = "gliner_entities.txt"

    # Process files
    process_files(input_folder, output_folder, public_keys_folder, entity_file)
