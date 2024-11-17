# Multilingual Document Anonymizer and Deanonymizer

This project processes documents in **English** and **Italian**, anonymizes sensitive information, encrypts the anonymized data, and provides a way to securely reconstruct the original content. It supports `.pdf`, `.docx`, and `.txt` files.

## Features

1. **Anonymization**:
   - Replaces sensitive entities (e.g., `PERSON`, `ORG`, `DATE`) with placeholders.
   - Entities to anonymize are configurable in a `entities.txt` file.

2. **Encryption**:
   - Uses **Hybrid Encryption**:
     - AES (256-bit) for anonymized data.
     - RSA (4096-bit) to encrypt the AES key.

3. **Language Support**:
   - Automatically detects and processes files in English and Italian.

4. **Reconstruction**:
   - Reverses the anonymization process to restore the original content using encrypted mappings.

5. **Folder-Based Workflow**:
   - Files are read from the `input` folder.
   - Processed files are saved to the `output` folder.
   - Reconstructed files are saved to the `reconstructed` folder.

## Folder Structure

```
.
├── input/               # Input folder for files to be processed
│   ├── file1.pdf
│   ├── file2.docx
│   └── file3.txt
├── output/              # Folder containing processed anonymized files
│   ├── file1_processed.json
│   ├── file2_processed.json
│   └── file3_processed.json
├── reconstructed/       # Folder containing reconstructed original files
│   ├── file1_reconstructed.txt
│   ├── file2_reconstructed.txt
│   └── file3_reconstructed.txt
├── entities.txt         # Configurable file for entity types to anonymize
├── private_key.pem      # RSA private key (generated automatically)
├── public_key.pem       # RSA public key (generated automatically)
├── anonymizer.py        # Main anonymizer script
├── deanonymizer.py      # Deanonymizer script
├── requirements.txt     # Python dependencies
└── README.md            # Project documentation
```

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-repo/multilingual-anonymizer.git
   cd multilingual-anonymizer
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Download spaCy Models**:
   ```bash
   python -m spacy download en_core_web_sm
   python -m spacy download it_core_news_sm
   ```

4. **Generate RSA Keys**:
   The `anonymizer.py` script automatically generates the RSA key pair (`private_key.pem` and `public_key.pem`) on its first run.

## Usage

### Anonymizer

1. **Prepare Input**:
   - Place your `.pdf`, `.docx`, and `.txt` files in the `input` folder.
   - Configure entity types to anonymize in the `entities.txt` file. Example:
     ```
     PERSON
     ORG
     GPE
     DATE
     LOC
     ```

2. **Run the Anonymizer**:
   ```bash
   python3 anonymizer.py
   ```

3. **Output**:
   - Anonymized files with encrypted mappings are saved in the `output` folder as `.json`.

### Deanonymizer

1. **Run the Deanonymizer**:
   ```bash
   python3 deanonymizer.py
   ```

2. **Output**:
   - Reconstructed original files are saved in the `reconstructed` folder as `.txt`.

## File Formats

### Output Folder (`output`):
Each file in the `output` folder is a JSON file with:
- **Anonymized Text**: Contains the input text with placeholders.
- **Encrypted Mapping**: Securely stores the mapping between placeholders and original entities.

Example:
```json
{
    "anonymized_text": "John works at {{ORG_0}}.",
    "encrypted_mapping": {
        "encrypted_aes_key": "BASE64_ENCRYPTED_AES_KEY",
        "iv": "BASE64_IV",
        "encrypted_data": "BASE64_ENCRYPTED_ENTITY_MAPPING"
    }
}
```

### Reconstructed Folder (`reconstructed`):
Each file in the `reconstructed` folder is a plain `.txt` file containing the original reconstructed text.

## How It Works

### Anonymizer Workflow
1. Extracts text from `.pdf`, `.docx`, or `.txt` files in the `input` folder.
2. Detects the language of the text (English or Italian).
3. Loads entity types from `entities.txt`.
4. Identifies and replaces entities with placeholders.
5. Encrypts the mapping of placeholders to original entities using:
   - AES encryption for the mapping data.
   - RSA encryption for the AES key.
6. Saves the anonymized text and encrypted mapping to the `output` folder.

### Deanonymizer Workflow
1. Reads JSON files from the `output` folder.
2. Decrypts the AES key and entity mapping using the RSA private key.
3. Replaces placeholders in the anonymized text with the original entities.
4. Saves the reconstructed text to the `reconstructed` folder.

## Requirements

- Python 3.7 or higher
- Dependencies (see `requirements.txt`)

## Notes

- Ensure `entities.txt` contains valid spaCy entity types (e.g., `PERSON`, `ORG`).
- Only `.pdf`, `.docx`, and `.txt` files are supported.
- Use consistent folder names (`input`, `output`, `reconstructed`) for seamless processing.
