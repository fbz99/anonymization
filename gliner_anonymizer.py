import json
import os
import base64
import argparse
from pathlib import Path
from tqdm import tqdm  # For progress bar
from PyPDF2 import PdfReader
from gliner import GLiNER
from langdetect import detect
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom


# Load GLiNER Models for Supported Languages
def load_gliner_models():
    """
    Load GLiNER models for supported languages.
    """
    return {
        "en": GLiNER.from_pretrained("gliner-community/gliner_medium-v2.5"),
        "it": GLiNER.from_pretrained("DeepMount00/GLiNER_ITA_LARGE")
    }


# Detect Language
def detect_language(text):
    """
    Detect the language of the given text using langdetect.
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


def count_tokens(text):
    """
    Count the number of tokens in a given text.
    """
    return len(text.split())


def anonymize_text(text, model, labels):
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


# Process Files
def process_files(input_folder, output_folder, public_keys_folder, entity_file, gliner_models):
    """
    Process files in the input folder, anonymize using GLiNER, and encrypt using public keys.
    """
    os.makedirs(output_folder, exist_ok=True)
    os.makedirs(readable_folder, exist_ok=True)

    # Load entity types to recognize
    with open(entity_file, "r", encoding="utf-8") as file:
        labels = [line.strip() for line in file if line.strip()]
    print(f"Loaded entity labels: {labels}")

    files = list(Path(input_folder).rglob("*"))
    for file_path in tqdm(files, desc="Processing files"):
        try:
            if file_path.suffix.lower() == ".pdf":
                # Extract text from PDF
                text = extract_text_from_pdf(file_path)
            elif file_path.suffix.lower() == ".txt":
                # Read text from TXT file
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
            if language_code not in gliner_models:
                print(f"Unsupported language detected for {file_path}: {language_code}. Skipping...")
                continue

            print(f"Detected language for {file_path}: {language_code.upper()}")

            # Select model based on language
            model = gliner_models[language_code]

            # Count input tokens
            input_token_count = count_tokens(text)

            # Anonymize text
            anonymized_text, entity_mapping = anonymize_text(text, model, labels)

            # Count output tokens
            output_token_count = count_tokens(anonymized_text)

            # Encrypt entity mapping for all public keys
            encrypted_mapping = hybrid_encrypt(json.dumps(entity_mapping, ensure_ascii=False), public_keys_folder)

            # Save anonymized text and encrypted mapping
            base_filename = Path(file_path).stem
            json_output_file = Path(output_folder) / f"{base_filename}_processed.json"
            with open(json_output_file, "w", encoding="utf-8") as file:
                json.dump(
                    {
                        "anonymized_text": anonymized_text,
                        "encrypted_mapping": encrypted_mapping,
                        "input_token_count": input_token_count,
                        "output_token_count": output_token_count,
                        "language": language_code,
                    },
                    file,
                    indent=4,
                    ensure_ascii=False,
                )

            # Save readable anonymized text
            readable_output_file = Path(readable_folder) / f"{base_filename}_anonymized.txt"
            with open(readable_output_file, "w", encoding="utf-8") as file:
                file.write(f"Anonymized Text:\n{anonymized_text}\n\nEntity Mapping:\n")
                for placeholder, original in entity_mapping:
                    file.write(f"{placeholder} -> {original}\n")
                file.write(f"\nInput Tokens: {input_token_count}\n")
                file.write(f"Output Tokens: {output_token_count}\n")
                file.write(f"Language: {language_code.upper()}\n")

            print(f"Processed {file_path} saved to {json_output_file} and {readable_output_file}.")
        except Exception as e:
            print(f"Error processing {file_path}: {e}")


if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Anonymize and encrypt text files and PDFs using GLiNER.")
    parser.add_argument(
        "--keygen",
        action="store_true",
        help="Generate a new RSA key pair (private_key.pem and public_keys/public_key.pem) and then process files.",
    )
    args = parser.parse_args()

    # Static folders
    input_folder = "input"
    output_folder = "output"
    readable_folder = "output/readable"
    public_keys_folder = "public_keys"
    entity_file = "gliner_entities.txt"

    if args.keygen:
        generate_keys()

    # Load GLiNER models for supported languages
    gliner_models = load_gliner_models()

    # Process files
    process_files(input_folder, output_folder, public_keys_folder, entity_file, gliner_models)
