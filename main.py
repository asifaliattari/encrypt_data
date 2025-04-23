import streamlit as st
import hashlib
import os
from cryptography.fernet import Fernet

# ---------- Load/Generate Encryption Key ----------
def load_key():
    key_file = "secret.key"
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
        return key

KEY = load_key()
cipher = Fernet(KEY)

# ---------- Session State Setup ----------
if "users" not in st.session_state:
    st.session_state.users = {}  # Format: { username: hashed_password }

if "current_user" not in st.session_state:
    st.session_state.current_user = None

if "user_data" not in st.session_state:
    st.session_state.user_data = {}  # Format: { username: [ { "text": encrypted, "passkey": hashed } ] }

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# ---------- Utility Functions ----------
def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def encrypt_text(text: str) -> str:
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted: str) -> str:
    return cipher.decrypt(encrypted.encode()).decode()

# ---------- UI ----------
st.title("🔐 Secure Data Encryption System")

# Sidebar Navigation
if st.session_state.current_user:
    menu = ["Home", "Store Data", "My Encrypted Data", "Logout"]
else:
    menu = ["Register", "Login"]

choice = st.sidebar.selectbox("Navigation", menu)

# ---------- Pages ----------

# 🔐 Register
if choice == "Register":
    st.subheader("📝 Create an Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in st.session_state.users:
                st.error("🚫 Username already exists.")
            else:
                st.session_state.users[username] = hash_text(password)
                st.success("✅ Account created! You can now log in.")
        else:
            st.error("⚠️ Please fill in both fields.")

# 🔑 Login
elif choice == "Login":
    st.subheader("🔑 Login to Your Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in st.session_state.users and st.session_state.users[username] == hash_text(password):
            st.session_state.current_user = username
            st.success(f"✅ Welcome, {username}!")
            st.rerun()

        else:
            st.error("❌ Invalid credentials.")

# 🏠 Home
elif choice == "Home":
    st.subheader(f"🏠 Welcome, {st.session_state.current_user}!")
    st.write("This app lets you securely store and retrieve encrypted data using a passkey.")

# 📦 Store Data
elif choice == "Store Data":
    st.subheader("📦 Store Encrypted Data")
    text = st.text_area("Enter text to encrypt:")
    passkey = st.text_input("Enter passkey:", type="password")

    if st.button("🔐 Encrypt & Save"):
        if text and passkey:
            encrypted = encrypt_text(text)
            hashed_passkey = hash_text(passkey)

            if st.session_state.current_user not in st.session_state.user_data:
                st.session_state.user_data[st.session_state.current_user] = []

            st.session_state.user_data[st.session_state.current_user].append({
                "text": encrypted,
                "passkey": hashed_passkey
            })

            st.success("✅ Data encrypted and saved.")
            st.info(f"🔒 Encrypted text (save it):\n\n{encrypted}")
        else:
            st.error("⚠️ Please fill in both fields.")

# 📂 My Encrypted Data
elif choice == "My Encrypted Data":
    st.subheader("📂 Your Encrypted Data")

    user_items = st.session_state.user_data.get(st.session_state.current_user, [])

    if user_items:
        for idx, item in enumerate(user_items):
            st.markdown(f"**🔐 Encrypted Text #{idx + 1}:**")
            st.code(item['text'], language="text")

            with st.expander("🔓 Decrypt this"):
                entered_passkey = st.text_input(f"Enter passkey for item #{idx + 1}", type="password", key=f"decrypt_{idx}")

                if st.button(f"Decrypt #{idx + 1}", key=f"btn_{idx}"):
                    if hash_text(entered_passkey) == item['passkey']:
                        decrypted = decrypt_text(item['text'])
                        st.success(f"✅ Decrypted:\n\n{decrypted}")
                        st.session_state.failed_attempts = 0
                    else:
                        st.session_state.failed_attempts += 1
                        remaining = 3 - st.session_state.failed_attempts
                        st.error(f"❌ Incorrect passkey. Attempts left: {remaining}")

                        if st.session_state.failed_attempts >= 3:
                            st.warning("🔒 Too many failed attempts! Please log in again.")
                            st.session_state.current_user = None
                            st.session_state.failed_attempts = 0
                            st.rerun()

    else:
        st.info("You haven't stored any encrypted data yet.")

# 🚪 Logout
elif choice == "Logout":
    st.session_state.current_user = None
    st.success("🔓 Logged out successfully.")
    st.rerun()

