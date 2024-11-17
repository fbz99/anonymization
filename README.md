# Multilingual Document Anonymizer and Encryptor

This project processes documents in **English** and **Italian**, anonymizes sensitive information, and encrypts the anonymized data for secure storage. It supports `.pdf`, `.docx`, and `.txt` files, processes them from an `input` folder, and saves the results in an `output` folder.

---

## Features

1. **Language Detection**:
   - Automatically detects the language of the input file's content.
   - Supports English (`en_core_web_sm`) and Italian (`it_core_news_sm`).

2. **File Support**:
   - Processes `.pdf`, `.docx`, and `.txt` files.
   - Skips unsupported file types and logs errors.

3. **Anonymization**:
   - Replaces sensitive entities (e.g., `PERSON`, `ORG`, `DATE`) with placeholders.

4. **Encryption**:
   - Uses **Hybrid Encryption**:
     - AES (256-bit) for anonymized data.
     - RSA (4096-bit) to encrypt the AES key.

5. **Folder Structure**:
   - Reads files from the `input` folder.
   - Outputs results to the `output` folder.

---

## Folder Structure


