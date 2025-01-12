# imports
import os
import json
import smtplib
from tkinter import messagebox
import sys

# find imports in /source
source_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'source')
sys.path.append(source_dir)

import cryptography
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import *
from tkinter import filedialog

sys.path.append(source_dir)

import darkdetect
import customtkinter as ctk

# finds user, key, and iv files
with open("source/user.txt", "r+b") as f:
    content = f.read()
    if not content.strip():
        with open('source/import.txt', 'w') as e:
          e.close()
        with open('source/export.txt', 'w') as e:
          e.close()
          f.close()
with open("source/import.txt", "r+b") as f:
    content = f.read()
    if not content.strip():
        import_empty = True
    else:
        import_empty = False
with open("source/export.txt", "r+b") as f:
    content = f.read()
    if not content.strip():
        export_empty = True
    else:
        export_empty = False
# find/make key
az1 = 78
bz1 = 235
az=os.urandom(az1)
bz=os.urandom(bz1)
if import_empty == False:
  with open('source/import.txt', 'rb') as f:
    temp = f.read()
    real1 = temp[az1:]
    real = real1[:-bz1]
    key = real
    f.close()
else:
  key = os.urandom(32)
swrite = az + key + bz
if import_empty == True:
  with open('source/import.txt', 'wb') as f:
    f.write(swrite)
    f.close()
# find/make iv
az1 = 264
bz1 = 43
az=os.urandom(az1)
bz=os.urandom(bz1)
if export_empty == False:
  with open('source/export.txt', 'rb') as f:
    temp = f.read()
    real1 = temp[az1:]
    real = real1[:-bz1]
    iv = real
    f.close()
else:
  iv = os.urandom(16)
swrite = az + iv + bz
if export_empty == True:
  with open('source/export.txt', 'wb') as f:
    f.write(swrite)
    f.close()
# find theme so customtkinter doesnt break
theme_path = "source/json/blue.json"
with open(theme_path) as f:
    theme = json.load(f)
backend = default_backend()
# function that quits the program
def exit(text="",ms=False):
  if ms == True:
    messagebox.showerror("   ", text)
  sys.exit(text)
# encrypt files
def encrypt_file(input_file_path, output_file_path, key):
    cipher = cryptography.hazmat.primitives.ciphers.Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    with open(input_file_path, 'rb') as input_file:
        input_data = input_file.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(input_data) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file_path, 'wb') as output_file:
        output_file.write(iv + ciphertext)
# decrypt files
def decrypt_file(input_file_path, output_file_path, key):

    with open(input_file_path, 'rb') as input_file:
        iv1 = input_file.read(16)
        ciphertext = input_file.read()
        input_file.close()

    cipher = cryptography.hazmat.primitives.ciphers.Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

    with open(output_file_path, 'wb+') as output_file:
        output_file.write(decrypted_data)

    with open(output_file_path, 'rb+') as f:
        data = f.read()
        input_file_path = str(input_file_path)
        input_file_path = str(input_file_path)
        if input_file_path.endswith('.json'):
          original_data = json.loads(data)
        else:
          original_data = data
    with open(input_file_path, 'rb+') as f:
        data = f.read()
        input_file_path = str(input_file_path)
        if input_file_path.endswith('.json'):
          decrypted_data = json.loads(data)
        else:
          decrypted_data = data

    assert original_data == decrypted_data
# opens the file selector for encryption
def encrypt_selected_file():
    input_file_path = filedialog.askopenfilename()
    if input_file_path:
        encrypt_file(input_file_path, input_file_path, key)
        loga(f"{input_file_path} encrypted successfully.")
    else:
        return
# opens the file selector for decryption
def decrypt_selected_file():
    input_file_path = filedialog.askopenfilename()
    if input_file_path:
        decrypt_file(input_file_path, input_file_path, key)
        loga(f"{input_file_path} decrypted successfully.")
    else:
        return
# change UI to light/dark mode
def change_mode(val):
  if val == "Light":
    ctk.set_appearance_mode("Light")
  elif val == "Dark":
    ctk.set_appearance_mode("Dark")
  elif val == "System":
    ctk.set_appearance_mode("System")
# login button function
def login(username_entry, password_entry, login_popup):
  username = username_entry.get()
  password = password_entry.get()
  decrypt_file('source/user.txt','source/user.txt',key)
  with open('source/user.txt', 'r') as f:
    ruser = str(f.readline()).strip()
    rpassword = str(f.readline())
  encrypt_file('source/user.txt','source/user.txt',key)
  if username == ruser and password == rpassword:
    login_popup.destroy()
  else:
    messagebox.showerror("Login Failed", "Your login attempt failed. Please try again.")
# resets the user.txt file so new login can be made
def reset_pwd(e1="", e2=""):
  if e1 != e2:
     messagebox.showerror("Error", "Wrong email.")
     return
  with open('source/user.txt', 'w+') as f:
    f.truncate(0)
    exit(text="Please run the program again to finalize this change.", ms=True)
# make sure that reset pwd has correct email
def forgot_password(email_entry):
    decrypt_file('source/user.txt','source/user.txt',key)
    with open('source/user.txt', 'r+') as f:
      remail = str(f.readline())
      remail = remail.strip()
      password = str(f.readline())
      f.close()
    encrypt_file('source/user.txt','source/user.txt',key)
    email = str(email_entry.get())
    reset_pwd(e1=email, e2=remail)
# makes the login UI
def show_login_popup():
    login_popup = tk.Tk()
    login_popup.title("Login")

    login_heading = tk.Label(login_popup, text="Login Form", bg="light gray", font=("Arial", 16, "bold"))
    login_heading.pack(fill="both", expand=True, padx=40, pady=10)

    username_label = tk.Label(login_popup, text="Email", font=("Arial", 12))
    username_label.pack(fill="both", expand=True, padx=40, pady=10)
    username_entry = tk.Entry(login_popup)
    username_entry.pack(fill="both", expand=True, padx=40, pady=10)

    password_label = tk.Label(login_popup, text="Password", font=("Arial", 12))
    password_label.pack(fill="both", expand=True, padx=40, pady=10)
    password_entry = tk.Entry(login_popup, show="*")
    password_entry.pack(fill="both", expand=True, padx=40, pady=10)

    login_button = tk.Button(login_popup, text="Login", command=lambda: login(username_entry, password_entry, login_popup))
    login_button.pack(fill="both", expand=True, padx=40, pady=10)

    forgot_password_padding = tk.Label(login_popup, text="")
    forgot_password_padding.pack(fill="both", expand=True, padx=40, pady=10)
    forgot_password_label = tk.Label(login_popup, text="Forgot Password", bg="light gray", font=("Arial", 16, "bold"))
    forgot_password_label.pack(fill="both", expand=True, padx=40, pady=10)

    email_label = tk.Label(login_popup, text="Email", font=("Arial", 12))
    email_label.pack(fill="both", expand=True, padx=40, pady=10)
    email_entry = tk.Entry(login_popup)
    email_entry.pack(fill="both", expand=True, padx=40, pady=10)

    forgot_password_button = tk.Button(login_popup, text="Reset Password", command=lambda: forgot_password(email_entry))
    forgot_password_button.pack(fill="both", expand=True, padx=40, pady=10)

    login_popup.protocol("WM_DELETE_WINDOW", exit)
    login_popup.geometry("400x500")
    login_popup.mainloop()
# adds user to user.txt
def signup(username_entry, password_entry, login_popup):
  email = username_entry.get()
  password = password_entry.get()
  with open('source/user.txt', 'w+') as f:
    f.write(email + "\n")
    f.write(password)
  encrypt_file('source/user.txt', 'source/user.txt', key)
  login_popup.destroy()
# make signup form
def show_signup_popup():
    login_popup = tk.Tk()
    login_popup.title("Signup")

    signup_heading = tk.Label(login_popup, text="Login Form", bg="light gray", font=("Arial", 16, "bold"))
    signup_heading.pack(fill="both", expand=True, padx=40, pady=10)

    username_label = tk.Label(login_popup, text="Email", font=("Arial", 12))
    username_label.pack(fill="both", expand=True, padx=40, pady=10)
    username_entry = tk.Entry(login_popup)
    username_entry.pack(fill="both", expand=True, padx=40, pady=10)

    password_label = tk.Label(login_popup, text="Password", font=("Arial", 12))
    password_label.pack(fill="both", expand=True, padx=40, pady=10)
    password_entry = tk.Entry(login_popup, show="*")
    password_entry.pack(fill="both", expand=True, padx=40, pady=10)

    login_button = tk.Button(login_popup, text="Signup", command=lambda: signup(username_entry, password_entry, login_popup))
    login_button.pack(fill="both", expand=True, padx=40, pady=10)
    login_popup.protocol("WM_DELETE_WINDOW", exit)
    login_popup.mainloop()
# checks user.txt and shows login/signup form
with open("source/user.txt", "r+b") as f:
    content = f.read()
    if not content.strip():
        show_signup_popup()
    else:
        show_login_popup()
# set up the UI
ctk.set_appearance_mode("Dark")
root = ctk.CTk()
root.title("File Encrypter")
# root.resizable(False,False)
audit = StringVar()

# logs whatever was encrypted/decrypted
def loga(text):
  with open('source/logs.txt', 'r') as f:
    global sv_text
    sv_text = str(f.read())
  if sv_text == "":
    e = text
  else:
    e = sv_text + "\n" + "---------------" + "\n" + text
  sv_text = e
  with open('source/logs.txt', 'w') as f:
    f.write(e)
    f.close()
  audit.set(e)
with open('source/logs.txt', 'r') as f:
  sv_text = str(f.read())
  audit.set(sv_text)
  f.close()
# clears the logs.txt file
def clear_logs():
  with open('source/logs.txt', 'w') as f:
    f.truncate(0)
    f.close()
  sv_text = ""
  text = ""
  e = ""
  audit.set(sv_text)
# adds widgets to UI and sets the logo
photo = PhotoImage(file = "source/logo.png").subsample(2)
root.iconphoto(False, photo)
encrypt_button = ctk.CTkButton(root, text="Encrypt File", command=encrypt_selected_file)
encrypt_button.pack(pady=10, padx=60, fill='both', expand=True)

decrypt_button = ctk.CTkButton(root, text="Decrypt File", command=decrypt_selected_file)
decrypt_button.pack(pady=10, padx=60, fill='both', expand=True)

loglabel = ctk.CTkLabel(root, text="Logs:", font=("Helvetica", 20))
loglabel.pack(pady=10, anchor="w", padx=10, fill='both', expand=True)

clrlog_button = ctk.CTkButton(root, text="Clear Logs", command=clear_logs, width=0)
clrlog_button.pack(pady=10, anchor="w", padx=100, fill='both', expand=True)

loglabel_audit = ctk.CTkScrollableFrame(root, width=170, height=0)
loglabel_audit.pack(expand=True, fill='both', padx=10, pady=10)
scroll = loglabel_audit._scrollbar
scroll.configure(height=140)

auditlabel = ctk.CTkLabel(loglabel_audit, textvariable=audit, font=("Helvetica", 15), wraplength=450, justify="center")
auditlabel.pack()

applabel = ctk.CTkLabel(root, text="Appearance Mode:", font=("Helvetica", 13))
applabel.pack(pady=10, anchor="w", padx=10, fill='both', expand=True)

optionmenu_1 = ctk.CTkOptionMenu(root, values=["Dark", "Light", "System"], command=change_mode)
optionmenu_1.pack(pady=10, padx = 100, anchor="w", fill='both', expand=True)
optionmenu_1.set("Dark")

# keeps the window running and sets it to 500x500 by default (resizeable)
root.geometry("500x500")
root.mainloop()