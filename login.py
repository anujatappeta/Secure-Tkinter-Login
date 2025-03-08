import tkinter as tk
from tkinter import messagebox
import bcrypt
import sqlite3

conn = sqlite3.connect("users.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
)
""")
conn.commit()

def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

def verify_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode("utf-8"), stored_password)

def register():
    username = username_entry.get()
    password = password_entry.get()

    if username == "" or password == "":
        messagebox.showerror("Error", "All fields are required!")
        return

    try:
        hashed_password = hash_password(password)
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        messagebox.showinfo("Success", "Registration successful!")
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Username already exists!")

def login():
    username = username_entry.get()
    password = password_entry.get()

    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    if result and verify_password(result[0], password):
        messagebox.showinfo("Login Success", "You successfully logged in.")
    else:
        messagebox.showerror("Error", "Invalid login")

window = tk.Tk()
window.title("Secure Login & Register")
window.geometry("340x440")
window.configure(bg="#333333")

frame = tk.Frame()
login_label = tk.Label(frame, text="Login / Register", bg="#333333", fg="#FF3399", font=("Arial", 20))
username_label = tk.Label(frame, text="Username", bg="#333333", fg="#FFFFFF", font=("Arial", 16))
username_entry = tk.Entry(frame, font=("Arial", 16))
password_label = tk.Label(frame, text="Password", bg="#333333", fg="#FFFFFF", font=("Arial", 16))
password_entry = tk.Entry(frame, show="*", font=("Arial", 16))
login_button = tk.Button(frame, text="Login", bg="#FF3399", fg="#FFFFFF", command=login)
register_button = tk.Button(frame, text="Register", bg="#3399FF", fg="#FFFFFF", command=register)

login_label.grid(row=0, column=0, columnspan=2, pady=20)
username_label.grid(row=1, column=0)
username_entry.grid(row=1, column=1, pady=10)
password_label.grid(row=2, column=0)
password_entry.grid(row=2, column=1, pady=10)
login_button.grid(row=3, column=0, columnspan=2, pady=10)
register_button.grid(row=4, column=0, columnspan=2, pady=10)

frame.pack()
window.mainloop()
