# AES-CBC Cipher Generator (Capstone Project)

Course project for TZVM163 Cisco: Python Programming (OpenEDG) at The Open University.

## Project Overview
This project, awarded a **93% Distinction**, implements a symmetric block cipher system based on modern professional standards. It simulates securing sensitive data strings using the **AES-256 algorithm**.

>Disclaimer: This project is for educational purposes only. Unsecured plain text documents should not be used to store sensitive data! ;)

## Technical Highlights
* **Security Logic:** Upgrades a mandatory 2-character weak key into a cryptographically strong 32-byte key using **PBKDF2 key derivation** with 1,000,000 iterations and **SHA512 hashing**.
* **Algorithm Standard:** Implements **AES-CBC mode** with PKCS7 padding, ensuring compliance with **ISO/IEC 18033-3** international standards.
* **Robust Error Handling:** Utilises custom exception classes and `try-except` blocks to catch input errors and ensure system resilience.
* **PEP8 Compliance:** Adheres strictly to the PEP8 style guide, including the 79-character line maximum for readability.

## Tech Stack
* **Python** (Core Logic & PEP8 Compliance)
* **PyCryptodome** (AES-256 & PKCS7 Padding)
* **Secrets** (Cryptographically Strong Randomness)
* **PBKDF2 & SHA512** (Secure Key Derivation)
