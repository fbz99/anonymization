import json
import os
import base64
import argparse
from pathlib import Path
from PyPDF2 import PdfReader
import spacy
from langdetect import detect
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom


# Load SpaCy Models for Supported Languages
def load_spacy_models():
    """
    Load SpaCy models for supported languages.
    """
    models = {
        "en": spacy.load("en_core_web_sm"),
        "it": spacy.load("it_core_news_sm")
    }
    return models


# Detect Language
def detect_language(text):
    """
    Detect the language of the given text using langdetect.
    Returns the detected language code.
    """
    try:
        return detect(text)
    except Exception as e:
        print(f"Error detecting language: {e}")
        return None


# RSA Key Generation
def generate_keys():
    """
    Generate RSA private and public keys, save them, and move the public key to the public_keys folder.
    """
    if os.path.exists("private_key.pem") and os.path.exists("public_keys/public_key.pem"):
        print("Keys already exist. Skipping key generation.")
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    public_key = private_key.public_key()

    # Save private key
    with open("private_key.pem", "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save public key
    public_key_path = Path("public_keys")
    public_key_path.mkdir(exist_ok=True)  # Create public_keys folder if it doesn't exist
    with open(public_key_path / "public_key.pem", "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print("Keys generated successfully! Private key: 'private_key.pem', Public key: 'public_keys/public_key.pem'.")


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


# Extract text from PDF
def extract_text_from_pdf(pdf_path):
    """
    Extract text from a PDF file using PyPDF2.
    """
    try:
        reader = PdfReader(pdf_path)
        text = ""
        for page in reader.pages:
            text += page.extract_text()
        return text
    except Exception as e:
        print(f"Error reading PDF file {pdf_path}: {e}")
        return None


# Anonymization Logic with SpaCy
def anonymize_text(text, nlp):
    """
    Anonymize text using SpaCy's named entity recognition (NER).
    Returns anonymized text and entity mapping.
    """
    doc = nlp(text)
    entity_mapping = []
    anonymized_text = text

    for ent in doc.ents:
        placeholder = f"{{{{{ent.label_}_{len(entity_mapping)}}}}}"
        anonymized_text = anonymized_text.replace(ent.text, placeholder)
        entity_mapping.append((placeholder, ent.text))

    return anonymized_text, entity_mapping


# Process Files
def process_files(input_folder, output_folder, public_keys_folder, spacy_models):
    """
    Process files in the input folder, anonymize text in multiple languages, and encrypt using public keys.
    """
    os.makedirs(output_folder, exist_ok=True)

    for file_path in Path(input_folder).rglob("*"):
        try:
            if file_path.suffix.lower() == ".pdf":
                # Extract text from PDF
                print(f"Processing PDF file {file_path}...")
                text = extract_text_from_pdf(file_path)
            elif file_path.suffix.lower() == ".txt":
                # Read text from TXT file
                print(f"Processing TXT file {file_path}...")
                with open(file_path, "r", encoding="utf-8") as file:
                    text = file.read()
            else:
                print(f"Skipping unsupported file type: {file_path}")
                continue

            if not text:
                print(f"Failed to extract text from {file_path}. Skipping...")
                continue

            # Detect language
            language_code = detect_language(text)
            if not language_code or language_code not in spacy_models:
                print(f"Unsupported language for file {file_path}. Skipping...")
                continue

            print(f"Detected language: {language_code}")

            # Anonymize text
            nlp = spacy_models[language_code]
            anonymized_text, entity_mapping = anonymize_text(text, nlp)

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
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Anonymize and encrypt text files and PDFs for multiple languages.")
    parser.add_argument(
        "--keygen",
        action="store_true",
        help="Generate a new RSA key pair (private_key.pem and public_keys/public_key.pem) and then process files.",
    )
    args = parser.parse_args()

    # Static folders
    input_folder = "input"
    output_folder = "output"
    public_keys_folder = "public_keys"

    if args.keygen:
        generate_keys()

    # Load SpaCy models for supported languages
    spacy_models = load_spacy_models()

    # Process files
    process_files(input_folder, output_folder, public_keys_folder, spacy_models)
