import streamlit as st
import hashlib
import base64
from cryptography.fernet import Fernet, InvalidToken

# ---------------- In-Memory Data Storage ----------------
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}  # Initialize in-memory storage for encrypted data

failed_attempts = 0

# ---------------- Helper Functions ----------------

# Create a Fernet cipher using the passkey
def get_cipher_from_passkey(passkey):
    key = hashlib.sha256(passkey.encode()).digest()  # 32-byte key
    return Fernet(base64.urlsafe_b64encode(key))

# Encrypt data
def encrypt_data(text, passkey):
    cipher = get_cipher_from_passkey(passkey)
    return cipher.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    try:
        cipher = get_cipher_from_passkey(passkey)
        decrypted = cipher.decrypt(encrypted_text.encode()).decode()
        failed_attempts = 0
        return decrypted
    except InvalidToken:
        failed_attempts += 1
        return None

# ---------------- Streamlit UI ----------------

st.set_page_config(page_title="Secure Data App", page_icon="🛡️")
st.title("🛡️ Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("🔍 Navigation", menu)

# ---------- HOME ----------
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    st.markdown("**Features:**")
    st.markdown("- Encrypt your sensitive data using a passkey")
    st.markdown("- Retrieve it securely with the correct passkey")
    st.markdown("- After 3 wrong attempts, system will require re-login")

# ---------- STORE DATA ----------
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")

    user_data = st.text_area("Enter your data:")
    passkey = st.text_input("Enter a secret passkey:", type="password")

    if st.button("🔐 Encrypt & Save"):
        if user_data and passkey:
            encrypted_text = encrypt_data(user_data, passkey)
            data_id = f"data_{len(st.session_state.stored_data) + 1}"
            st.session_state.stored_data[data_id] = {"encrypted_text": encrypted_text}
            st.success("✅ Data encrypted and saved!")
            st.code(encrypted_text)
        else:
            st.error("⚠️ Please enter both data and passkey.")

# ---------- RETRIEVE DATA ----------
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Encrypted Data")

    if st.session_state.stored_data:
        selected_key = st.selectbox("Select Encrypted Data", list(st.session_state.stored_data.keys()))
        passkey = st.text_input("Enter your passkey:", type="password")

        if st.button("🔓 Decrypt"):
            encrypted_text = st.session_state.stored_data[selected_key]["encrypted_text"]
            decrypted_text = decrypt_data(encrypted_text, passkey)

            if decrypted_text:
                st.success("✅ Decryption successful!")
                st.text_area("Your decrypted data:", decrypted_text, height=200)
            else:
                st.error(f"❌ Incorrect passkey! Attempts left: {3 - failed_attempts}")
                if failed_attempts >= 3:
                    st.warning("🔐 Too many failed attempts! Redirecting to Login...")
                    st.experimental_rerun()
    else:
        st.info("ℹ️ No data found. Please store some data first.")

# ---------- LOGIN PAGE ----------
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            failed_attempts = 0
            st.success("✅ Reauthorized successfully!")
            st.info("Now go to 'Retrieve Data' to continue.")
        else:
            st.error("❌ Incorrect master password.")
