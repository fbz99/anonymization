Here’s a comprehensive `README.md` for your project in its current state.

---

# Anonymizer and Deanonymizer

This project provides a system for anonymizing text from various input file formats (PDFs, TXT files), securely storing entity mappings, and deanonymizing reworked text returned by a Large Language Model (LLM). The anonymizer processes input files and generates anonymized outputs and encrypted entity mappings, while the deanonymizer reconstructs the original text using mappings for the corresponding LLM responses.

## Features

- **Anonymizer**:
  - Processes multiple input files from the `input` folder.
  - Supports PDFs and TXT file formats.
  - Generates anonymized text files and encrypted mappings for secure storage.
  - Saves anonymized outputs to the `output` folder.

- **Deanonymizer**:
  - Processes reworked text returned by the LLM from the `response` folder.
  - Matches reworked text with encrypted mappings stored in the `output` folder.
  - Reconstructs and saves the original text in the `reconstructed` folder.

- **Security**:
  - Uses RSA (4096-bit keys) for public/private key encryption.
  - AES encryption ensures secure mapping storage.

## Installation

### Prerequisites

1. **Python**: Ensure Python 3.8 or higher is installed.
2. **Required Libraries**:
   Install the dependencies using the following command:
   ```bash
   pip install -r requirements.txt
   ```

   **Dependencies**:
   - `PyPDF2`: For extracting text from PDF files.
   - `cryptography`: For secure encryption and decryption.

### Folder Structure

Ensure the following folder structure exists before running the scripts:

```
.
├── input/                 # Input files to be anonymized (PDFs, TXT).
├── output/                # Anonymized text and encrypted mappings.
├── response/              # Reworked text returned by the LLM.
├── reconstructed/         # Reconstructed original text files.
├── public_keys/           # Folder for public keys.
├── private_key.pem        # Private key (generated with --keygen).
├── anonymizer.py          # Anonymizer script.
├── deanonymizer.py        # Deanonymizer script.
├── entities.txt           # List of entities to anonymize.
├── requirements.txt       # Dependencies for the project.
```

## Usage

### 1. **Generate RSA Keys**
To generate RSA public/private keys for secure mapping storage, use:
```bash
python3 anonymizer.py --keygen
```

- The private key is saved as `private_key.pem`.
- The public key is saved in the `public_keys` folder as `public_key.pem`.

### 2. **Anonymize Input Files**
Place your input files (`.pdf`, `.txt`) in the `input` folder, then run:
```bash
python3 anonymizer.py
```

- Anonymized text files are saved in the `output` folder with the suffix `_processed.json`.
- Encrypted mappings for each file are included in the corresponding JSON file.

### 3. **Send to LLM**
Send the anonymized text files to the LLM for processing. Save the LLM's reworked text in the `response` folder. Ensure the placeholders in the text remain unchanged.

### 4. **Deanonymize LLM Responses**
To reconstruct the original text from the LLM’s reworked response, run:
```bash
python3 deanonymizer.py
```

- The deanonymized files will be saved in the `reconstructed` folder with the suffix `_reconstructed.txt`.

### Optional Arguments
- **Anonymizer**:
  - `--keygen`: Generate RSA keys before processing files.

- **Deanonymizer**:
  - `--private_key`: Specify a custom private key path. Defaults to `private_key.pem`.

## Example Workflow

1. **Anonymization**:
   - Input: `input/example.txt`
   - Output: `output/example_processed.json`

2. **LLM Response**:
   - Reworked text from LLM: `response/example_anonymized.txt`

3. **Deanonymization**:
   - Reconstructed output: `reconstructed/example_reconstructed.txt`

## Security Notes

- **Keys**: Keep the `private_key.pem` file secure. Distribute only the `public_key.pem` for encryption.
- **Mappings**: Encrypted mappings ensure sensitive data cannot be accessed without the private key.

## Troubleshooting

- **No Files Found**:
  - Ensure input files are placed in the `input` folder for anonymization or the `response` folder for deanonymization.

- **Error: Mapping File Not Found**:
  - Verify that the corresponding mapping exists in the `output` folder.

- **Unsupported File Types**:
  - The scripts currently support `.pdf` and `.txt` formats.

## License

This project is licensed under the MIT License.

---

Let me know if you'd like additional sections or changes!