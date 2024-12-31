import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import random
import time
import datetime
import base64
import os

# ------------------------------------------
# Global Variables
# ------------------------------------------
current_user = None

# File for storing user credentials
USER_CREDENTIALS_FILE = "users.txt"

# Function to encode
def encode(key, clear):
    try:
        enc = []
        for i in range(len(clear)):
            key_c = key[i % len(key)]
            enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
            enc.append(enc_c)
        return base64.urlsafe_b64encode("".join(enc).encode()).decode()
    except Exception as e:
        messagebox.showerror("Error", f"Encoding failed: {e}")

# Function to decode
def decode(key, enc):
    try:
        dec = []
        enc = base64.urlsafe_b64decode(enc).decode()
        for i in range(len(enc)):
            key_c = key[i % len(key)]
            dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
            dec.append(dec_c)
        return "".join(dec)
    except Exception as e:
        messagebox.showerror("Error", f"Decoding failed: {e}")

# Function to reset all fields
def reset():
    rand.set("")
    Msg.set("")
    key.set("")
    mode.set("")
    Result.set("")
    status_var.set("Status: Ready")
    char_count_label.config(text="Character Count: 0")
    progress["value"] = 0
    progress_label.config(text="Processing...")

# Function to exit the application
def exit_app():
    root.destroy()

# Function to process the message
def process_message():
    clear = Msg.get()
    k = key.get()
    m = mode.get().lower()

    if not clear or not k or not m:
        messagebox.showwarning("Input Error", "All fields are required!")
        return

    if m not in ['e', 'd']:
        messagebox.showwarning("Mode Error", "Mode must be 'e' for encrypt or 'd' for decrypt!")
        return

    if len(k) < 4:
        messagebox.showwarning("Key Error", "Key must be at least 4 characters long!")
        return

    status_var.set("Status: Processing...")
    root.update_idletasks()

    # Simulate progress while processing
    simulate_progress()

    try:
        if m == 'e':
            Result.set(encode(k, clear))
        elif m == 'd':
            Result.set(decode(k, clear))
        status_var.set("Status: Process Complete")
    except Exception as e:
        status_var.set(f"Status: Error ({e})")

# Function to save the result to a file
def save_to_file():
    result = Result.get()
    if not result:
        messagebox.showwarning("Save Error", "No result to save!")
        return

    file_path = filedialog.asksaveasfilename(defaultextension=".txt", 
                                             filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(result)
        messagebox.showinfo("Saved", "Result saved successfully!")

# Function to count characters in the message
def count_characters(*args):
    char_count_label.config(text=f"Character Count: {len(Msg.get())}")

# ------------------------------------------
# Login and Sign-Up System
# ------------------------------------------
def save_credentials(username, password):
    with open(USER_CREDENTIALS_FILE, "a") as file:
        file.write(f"{username}:{password}\n")

def validate_login(username, password):
    if not os.path.exists(USER_CREDENTIALS_FILE):
        return False
    with open(USER_CREDENTIALS_FILE, "r") as file:
        for line in file:
            stored_username, stored_password = line.strip().split(":")
            if username == stored_username and password == stored_password:
                return True
    return False

def login():
    username = username_var.get()
    password = password_var.get()

    if validate_login(username, password):
        global current_user
        current_user = username
        login_frame.pack_forget()
        main_interface()
    else:
        messagebox.showerror("Login Failed", "Invalid username or password!")

def sign_up():
    username = username_var.get()
    password = password_var.get()

    if not username or not password:
        messagebox.showwarning("Input Error", "Both fields are required!")
        return

    save_credentials(username, password)
    messagebox.showinfo("Sign-Up Successful", "Account created successfully! Please log in.")
    reset_login_fields()

def reset_login_fields():
    username_var.set("")
    password_var.set("")

def logout():
    global current_user
    current_user = None
    for widget in root.winfo_children():
        widget.destroy()
    login_interface()

# ------------------------------------------
# GUI Design
# ------------------------------------------
def login_interface():
    global login_frame

    login_frame = tk.Frame(root, bg="#f0f8ff", pady=20)
    login_frame.pack(fill="both", expand=True)

    tk.Label(login_frame, text="Secure Messaging App", font=('arial', 24, 'bold'), bg="#f0f8ff", fg="#333366").pack(pady=10)

    tk.Label(login_frame, text="Username", font=('arial', 14), bg="#f0f8ff").pack(pady=5)
    tk.Entry(login_frame, textvariable=username_var, font=('arial', 14)).pack(pady=5)

    tk.Label(login_frame, text="Password", font=('arial', 14), bg="#f0f8ff").pack(pady=5)
    tk.Entry(login_frame, textvariable=password_var, font=('arial', 14), show="*").pack(pady=5)

    button_frame = tk.Frame(login_frame, bg="#f0f8ff")
    button_frame.pack(pady=10)

    tk.Button(button_frame, text="Login", command=login, bg="#228b22", font=('arial', 14), padx=10, pady=5).grid(row=0, column=0, padx=5)
    tk.Button(button_frame, text="Sign Up", command=sign_up, bg="#ff4500", font=('arial', 14), padx=10, pady=5).grid(row=0, column=1, padx=5)

def main_interface():
    # Header Frame
    header_frame = tk.Frame(root, bg="#4682b4", pady=10)
    header_frame.pack(fill="x")

    header_label = tk.Label(header_frame, text=f"Welcome {current_user}", 
                            font=('helvetica', 24, 'bold'), bg="#4682b4", fg="white")
    header_label.pack()

    time_label = tk.Label(header_frame, text=time.asctime(time.localtime(time.time())),
                          font=('arial', 12), bg="#4682b4", fg="white")
    time_label.pack()

    tk.Button(header_frame, text="Logout", command=logout, bg="#ff6347", font=('arial', 14), padx=10, pady=5).pack(side="right")

    # Main Content Frame
    content_frame = tk.Frame(root, padx=10, pady=10)
    content_frame.pack(fill="both", expand=True)

    create_label_entry(content_frame, "Name:", rand, 0)
    create_label_entry(content_frame, "Message:", Msg, 1)
    create_label_entry(content_frame, "Key:", key, 2)
    create_label_entry(content_frame, "Mode (e for encrypt, d for decrypt):", mode, 3)

    # Result Field
    result_label = tk.Label(content_frame, text="Result:", font=('arial', 14))
    result_label.grid(row=4, column=0, sticky="w", pady=5)
    result_entry = tk.Entry(content_frame, textvariable=Result, font=('arial', 14), width=30, state="readonly")
    result_entry.grid(row=4, column=1, pady=5)

    # Character Counter
    global char_count_label
    char_count_label = tk.Label(content_frame, text="Character Count: 0", font=('arial', 12), fg="gray")
    char_count_label.grid(row=5, column=1, sticky="e")

    Msg.trace_add("write", count_characters)

    # Progress bar for showing process progress
    global progress
    progress = ttk.Progressbar(content_frame, orient="horizontal", length=300, mode="determinate")
    progress.grid(row=6, column=1, pady=5)

    global progress_label
    progress_label = tk.Label(content_frame, text="Processing...", font=('arial', 12), fg="gray")
    progress_label.grid(row=7, column=1, pady=5)

    # Buttons
    button_frame = tk.Frame(root, pady=10)
    button_frame.pack()

    create_button(button_frame, "Process", process_message, "#add8e6", 0, 0)
    create_button(button_frame, "Reset", reset, "#90ee90", 0, 1)
    create_button(button_frame, "Exit", exit_app, "#ff4500", 0, 2)
    create_button(button_frame, "Save Result", save_to_file, "#f0e68c", 0, 3)

    # Status Bar
    global status_var
    status_var = tk.StringVar()
    status_var.set("Status: Ready")

    status_bar = tk.Label(root, textvariable=status_var, font=('arial', 12), bd=1, relief="sunken", anchor="w")
    status_bar.pack(side="bottom", fill="x")

# Helper function to create labels and entries
def create_label_entry(parent, label_text, textvariable, row):
    label = tk.Label(parent, text=label_text, font=('arial', 14))
    label.grid(row=row, column=0, sticky="w", pady=5)
    entry = tk.Entry(parent, textvariable=textvariable, font=('arial', 14), width=30)
    entry.grid(row=row, column=1, pady=5)

# Helper function to create buttons
def create_button(parent, text, command, bg, row, column):
    button = tk.Button(parent, text=text, command=command, bg=bg, font=('arial', 14), padx=10, pady=5)
    button.grid(row=row, column=column, padx=10)

# Function to simulate progress
def simulate_progress(): 
    progress["value"] = 0
    progress_label.config(text="Processing...")
    for i in range(101):  # Simulating the progress from 0 to 100
        progress["value"] = i
        progress.update()
        time.sleep(0.02)  # Adjust the sleep for speed of progress
    progress_label.config(text="Completed!") 

# ------------------------------------------
# Application Initialization
# ------------------------------------------
root = tk.Tk()
root.title("Advanced Secure Messaging Application")
root.geometry("950x750")

username_var = tk.StringVar()
password_var = tk.StringVar()
rand = tk.StringVar()
Msg = tk.StringVar()
key = tk.StringVar()
mode = tk.StringVar()
Result = tk.StringVar()

login_interface()
root.mainloop()
