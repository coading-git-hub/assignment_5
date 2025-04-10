import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode, urlsafe_b64decode
from hashlib import pbkdf2_hmac

# Data file & salt
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60  # seconds

# Session State Initialization
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# Load Data
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# Save Data
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# Generate Encryption Key
def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000, dklen=32)
    return urlsafe_b64encode(key)

# Password Hashing
def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

# Encrypt Text
def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

# Decrypt Text
def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Load Stored Data
stored_data = load_data()

# Title & Menu
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home Page
if choice == "Home":
    st.subheader("Welcome To My Data Encryption System Using Streamlit!")
    st.markdown("""
        - Register new users securely.  
        - Store sensitive data with encryption.  
        - Retrieve data using your unique passkey.  
        - 3 wrong login attempts = Lockout for 60 seconds.
    """)

# Register Page
elif choice == "Register":
    st.subheader("✏️ Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ User already exists.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("✅ User registered successfully!")
        else:
            st.error("Both fields are required.")

# Login Page
elif choice == "Login":
    st.subheader("🔑 User Login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"Too many failed attempts. ⏱️ Please wait {remaining} seconds.")
    else:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.success(f'👋 Welcome {username}!')
            else:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f'❌ Invalid Credentials! Attempts left: {remaining}')

                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.error("🚫 Too many failed attempts. Locked out for 60 seconds.")

# Store Data Page
elif choice == "Store Data":
    if st.session_state.authenticated_user:
        st.subheader("🔒 Store Your Sensitive Data")
        data_input = st.text_area("Enter Data to Encrypt")
        passkey = st.text_input("Enter Passkey for Encryption", type="password")

        if st.button("Encrypt & Save"):
            if data_input and passkey:
                encrypted = encrypt_text(data_input, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data Encrypted & Saved Successfully!")
            else:
                st.error("All fields are required!")
    else:
        st.warning("Please login first!")

# Retrieve Data Page
elif choice == "Retrieve Data":
    if st.session_state.authenticated_user:
        st.subheader("🔓 Retrieve Your Encrypted Data")
        passkey = st.text_input("Enter Passkey to Decrypt Data", type="password")

        if st.button("Retrieve"):
            user_data = stored_data[st.session_state.authenticated_user]["data"]
            if user_data:
                st.info("Decrypted Data:")
                for idx, encrypted in enumerate(user_data, 1):
                    decrypted = decrypt_text(encrypted, passkey)
                    if decrypted:
                        st.write(f"{idx}. {decrypted}")
                    else:
                        st.error(f"{idx}. Invalid Passkey!")
            else:
                st.warning("No data found!")
    else:
        st.warning("Please login first!")
