import spacy
import json
import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pathlib import Path
from PyPDF2 import PdfReader
from docx import Document
from os import urandom
from langdetect import detect, DetectorFactory

# Ensure consistent language detection results
DetectorFactory.seed = 0


# RSA Key Management
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    public_key = private_key.public_key()

    with open("private_key.pem", "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open("public_key.pem", "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    print("RSA key pair generated and saved.")


def load_keys():
    with open("private_key.pem", "rb") as private_file:
        private_key = serialization.load_pem_private_key(
            private_file.read(),
            password=None,
        )

    with open("public_key.pem", "rb") as public_file:
        public_key = serialization.load_pem_public_key(public_file.read())

    return private_key, public_key


# Hybrid Encryption Functions
def hybrid_encrypt(data, public_key):
    aes_key = urandom(32)  # 256-bit AES key
    iv = urandom(16)  # Initialization vector for AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return {
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "encrypted_data": base64.b64encode(encrypted_data).decode(),
    }


# Text Extraction Functions
def extract_text_from_pdf(file_path):
    reader = PdfReader(file_path)
    text = ""
    for page in reader.pages:
        text += page.extract_text()
    return text


def extract_text_from_docx(file_path):
    doc = Document(file_path)
    return "\n".join([p.text for p in doc.paragraphs])


def extract_text_from_txt(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return file.read()


def get_text_from_file(file_path):
    if file_path.endswith(".pdf"):
        return extract_text_from_pdf(file_path)
    elif file_path.endswith(".docx"):
        return extract_text_from_docx(file_path)
    elif file_path.endswith(".txt"):
        return extract_text_from_txt(file_path)
    else:
        raise ValueError(f"Unsupported file type for {file_path}. Supported types: .pdf, .docx, .txt")


# Language Detection
def detect_language(text):
    try:
        lang = detect(text)
        if lang == "en":
            return "en"
        elif lang == "it":
            return "it"
        else:
            return None
    except Exception as e:
        print(f"Language detection failed: {e}")
        return None


# Load Entities from Configuration File
def load_entities(entity_file):
    """
    Load entity types from a configuration file.
    Each line in the file represents an entity type (e.g., PERSON, ORG).
    """
    if not os.path.exists(entity_file):
        raise FileNotFoundError(f"Entity file '{entity_file}' not found.")
    with open(entity_file, "r", encoding="utf-8") as file:
        entities = [line.strip() for line in file.readlines() if line.strip()]
    print(f"Loaded entities: {entities}")
    return entities


# NER and Placeholder Management
def anonymize_text(text, nlp, entities_to_anonymize):
    doc = nlp(text)
    entities = []
    anonymized_text = text

    for i, ent in enumerate(doc.ents):
        if ent.label_ in entities_to_anonymize:
            placeholder = f"{{{{{ent.label_}_{i}}}}}"
            entities.append((placeholder, ent.text))
            anonymized_text = anonymized_text.replace(ent.text, placeholder)

    return anonymized_text, entities


def process_files(input_folder, output_folder, entity_file):
    os.makedirs(output_folder, exist_ok=True)
    private_key, public_key = load_keys()

    # Load entity types to anonymize
    entities_to_anonymize = load_entities(entity_file)

    for file_path in Path(input_folder).rglob("*"):
        file_path = str(file_path)
        if not file_path.endswith((".pdf", ".docx", ".txt")):
            continue

        try:
            # Extract text
            text = get_text_from_file(file_path)
            print(f"Processing {file_path}...")

            # Detect language
            lang = detect_language(text)
            if lang == "en":
                nlp = spacy.load("en_core_web_sm")
            elif lang == "it":
                nlp = spacy.load("it_core_news_sm")
            else:
                print(f"Skipping {file_path}: Unsupported language detected.")
                continue

            # Anonymize text
            anonymized_text, entity_mapping = anonymize_text(text, nlp, entities_to_anonymize)

            # Encrypt entity mapping
            encrypted_mapping = hybrid_encrypt(json.dumps(entity_mapping, ensure_ascii=False), public_key)

            # Save the results to the output folder
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
    # Static folders
    input_folder = "input"
    output_folder = "output"
    entity_file = "entities.txt"  # File listing entities to anonymize

    # Process files
    process_files(input_folder, output_folder, entity_file)
