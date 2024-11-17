# Multilingual Document Anonymizer and Deanonymizer

This project processes documents in **English** and **Italian**, anonymizes sensitive information using customizable NER models, encrypts the anonymized data, and provides a way to securely reconstruct the original content using user-specific keys. It supports `.pdf`, `.docx`, and `.txt` files.

---

## Features

1. **Anonymization**:
   - Two anonymizers are available:
     - **Default Anonymizer**: Uses spaCy for Named Entity Recognition (NER).
     - **GLiNER Anonymizer**: Uses the GLiNER library for advanced and flexible NER.
   - Replace sensitive entities (e.g., `Person`, `Date`) with placeholders.
   - Supports configurable entities for each anonymizer using separate configuration files.

2. **Encryption**:
   - Uses **Hybrid Encryption**:
     - AES (256-bit) for anonymized data.
     - RSA (4096-bit) to encrypt the AES key.
   - Encrypts the AES key for multiple public keys, allowing multiple users to access the same anonymized data securely.

3. **Deanonymization**:
   - Automatically identifies the user based on their private key.
   - Reverses anonymization by replacing placeholders with the original data.

4. **Language Support**:
   - Automatically detects and processes files in English and Italian.

5. **Folder-Based Workflow**:
   - Files are read from the `input` folder.
   - Processed files are saved to the `output` folder.
   - Reconstructed files are saved to the `reconstructed` folder.

---

## Folder Structure

```
.
├── input/                 # Input folder for files to be processed
│   ├── example.txt
├── output/                # Output folder for anonymized files
│   ├── example_processed.json
├── reconstructed/         # Folder containing reconstructed original files
│   ├── example_reconstructed.txt
├── public_keys/           # Folder containing public keys for encryption
│   ├── user1_public_key.pem
│   ├── user2_public_key.pem
├── entities.txt           # Entity configuration for default anonymizer
├── gliner_entities.txt    # Entity configuration for GLiNER anonymizer
├── anonymizer.py          # Default anonymizer script (spaCy)
├── gliner_anonymizer.py   # GLiNER-based anonymizer script
├── deanonymizer.py        # Deanonymizer script
├── requirements.txt       # Python dependencies
└── README.md              # Project documentation
```

---

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

4. **Install GLiNER**:
   ```bash
   pip install gliner
   ```

5. **Set Up Keys**:
   - Place your public keys in the `public_keys` folder.
   - Ensure each user has a private key that corresponds to a public key.

---

## Usage

### Default Anonymizer

1. **Prepare Input**:
   - Place `.pdf`, `.docx`, and `.txt` files in the `input` folder.
   - Configure entities in `entities.txt`. Example:
     ```
     PERSON
     ORG
     DATE
     GPE
     ```

2. **Run the Anonymizer**:
   ```bash
   python3 anonymizer.py
   ```

3. **Output**:
   - Anonymized files with encrypted mappings are saved in the `output` folder as `.json`.

---

### GLiNER Anonymizer

1. **Prepare Input**:
   - Place `.txt` files in the `input` folder (GLiNER currently supports text files).
   - Configure entities in `gliner_entities.txt`. Example:
     ```
     Person
     Date
     Organization
     Location
     ```

2. **Run the GLiNER Anonymizer**:
   ```bash
   python3 gliner_anonymizer.py
   ```

3. **Output**:
   - Anonymized files with encrypted mappings are saved in the `output` folder as `.json`.

---

### Deanonymizer

1. **Run the Deanonymizer**:
   ```bash
   python3 deanonymizer.py --private_key path/to/my_private_key.pem
   ```

   - Replace `path/to/my_private_key.pem` with the path to your private key.

2. **Output**:
   - Reconstructed original files are saved in the `reconstructed` folder as `.txt`.

---

## File Formats

### Output Folder (`output`):
Each file in the `output` folder is a JSON file with:
- **Anonymized Text**: Contains the input text with placeholders.
- **Encrypted Mapping**: Securely stores the mapping between placeholders and original entities.

Example:
```json
{
    "anonymized_text": "{{Person_0}} works at {{Organization_0}}.",
    "encrypted_mapping": {
        "encrypted_aes_keys": {
            "user1_public_key": "BASE64_ENCRYPTED_AES_KEY_FOR_USER1",
            "user2_public_key": "BASE64_ENCRYPTED_AES_KEY_FOR_USER2"
        },
        "iv": "BASE64_IV",
        "encrypted_data": "BASE64_ENCRYPTED_ENTITY_MAPPING"
    }
}
```

---

## How It Works

### Default Anonymizer Workflow (spaCy)
1. Extracts text from `.pdf`, `.docx`, or `.txt` files in the `input` folder.
2. Detects the language of the text (English or Italian).
3. Loads entity types from `entities.txt`.
4. Identifies and replaces entities with placeholders.
5. Encrypts the mapping of placeholders to original entities using:
   - AES encryption for the mapping data.
   - RSA encryption for the AES key, for each public key in the `public_keys` folder.
6. Saves the anonymized text and encrypted mapping to the `output` folder.

### GLiNER Anonymizer Workflow
1. Reads text files (`.txt`) from the `input` folder.
2. Uses GLiNER to identify entities specified in `gliner_entities.txt`.
3. Replaces identified entities with placeholders.
4. Encrypts the mapping of placeholders to original entities using:
   - AES encryption for the mapping data.
   - RSA encryption for the AES key, for each public key in the `public_keys` folder.
5. Saves the anonymized text and encrypted mapping to the `output` folder.

### Deanonymizer Workflow
1. Reads JSON files from the `output` folder.
2. Automatically identifies the corresponding `user_id` by matching the user's private key with a public key in the `public_keys` folder.
3. Decrypts the AES key and entity mapping using the user's private key.
4. Replaces placeholders in the anonymized text with the original entities.
5. Saves the reconstructed text to the `reconstructed` folder.

---

## Requirements

- Python 3.7 or higher
- Dependencies (see `requirements.txt`)

---

## Notes

- **Entity Files**:
  - Use `entities.txt` for the default anonymizer (spaCy).
  - Use `gliner_entities.txt` for the GLiNER anonymizer.
- **File Formats**:
  - The default anonymizer supports `.pdf`, `.docx`, and `.txt` files.
  - The GLiNER anonymizer supports `.txt` files only.
- Use consistent folder names (`input`, `output`, `reconstructed`, `public_keys`) for seamless processing.
- Ensure your private key matches one of the public keys in the `public_keys` folder.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
```
