# 🔐 Secure Data Encryption System

A simple yet powerful Streamlit application that allows users to securely encrypt and store sensitive data using a passkey. Built with Python, this app ensures that user data remains confidential through strong hashing and encryption techniques.

---

## 🚀 Features

- 📝 **User Registration & Login**  
  Create and log into a secure account to manage your encrypted data.

- 🔐 **Encrypt Text with a Passkey**  
  Your data is encrypted using Fernet (symmetric encryption), and your passkey is hashed for comparison.

- 📦 **Store & Retrieve Encrypted Data**  
  Save encrypted data securely and view it later with the correct passkey.

- 🔓 **Decrypt with Passkey**  
  Only users with the correct passkey can decrypt and view the original text.

- 🛡️ **Security Measures**  
  - Passwords and passkeys are hashed using SHA-256.  
  - Data is encrypted using `cryptography.fernet`.  
  - Tracks failed attempts to protect from brute-force attacks.

---

## 🛠️ Technologies Used

- [Streamlit](https://streamlit.io/) – UI Framework
- [cryptography](https://cryptography.io/) – For Fernet encryption
- `hashlib` – For SHA-256 hashing
- `os` – For secure key management

---

## 📦 Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/secure-data-encryption.git
    cd secure-data-encryption
    ```

2. **Create a virtual environment (optional but recommended)**:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3. **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

4. **Run the app**:
    ```bash
    streamlit run app.py
    ```

---

## 📁 File Structure

# encrypt_data
