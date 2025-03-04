import itertools
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import threading

CORRECT_PASSWORD = "acdan"

def dictionary_attack(dictionary_file, output_box):
    """Attempts login using a predefined dictionary file."""
    try:
        with open(dictionary_file, "r") as file:
            for password in file:
                password = password.strip()
                output_box.insert(tk.END, f"Trying: {password}\n")
                output_box.yview(tk.END)  # Auto-scroll
                if password == CORRECT_PASSWORD:
                    output_box.insert(tk.END, f"[+] Correct password found: {password}\n")
                    return True
    except FileNotFoundError:
        output_box.insert(tk.END, "[!] Dictionary file not found!\n")
    
    output_box.insert(tk.END, "[-] Dictionary attack failed.\n")
    return False

def brute_force_attack(output_box, length):
    """Tries all possible alphabetical combinations of a given length."""
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for guess in itertools.product(chars, repeat=length):
        guess_password = "".join(guess)
        output_box.insert(tk.END, f"Trying: {guess_password}\n")
        output_box.yview(tk.END)  
        if guess_password == CORRECT_PASSWORD:
            output_box.insert(tk.END, f"[+] Correct password found using brute force: {guess_password}\n")
            return True
    output_box.insert(tk.END, "[-] Brute force attack failed.\n")
    return False

def start_attack():
    username = username_entry.get()
    if not username:
        messagebox.showerror("Error", "Please enter a username!")
        return

    output_box.delete(1.0, tk.END)  
    output_box.insert(tk.END, f"[+] Starting attack for user: {username}\n")
    
    dictionary_file = "dictionary.txt"
    attack_type = attack_type_var.get()
    brute_force_length = int(length_entry.get())

    def attack_process():
        if attack_type in ["Dictionary", "Both"]:
            if not dictionary_attack(dictionary_file, output_box) and attack_type == "Dictionary":
                return
        if attack_type in ["Brute Force", "Both"]:
            output_box.insert(tk.END, "[+] Attempting brute force attack...\n")
            brute_force_attack(output_box, brute_force_length)

    threading.Thread(target=attack_process, daemon=True).start()

def select_dictionary_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        dictionary_file_entry.delete(0, tk.END)
        dictionary_file_entry.insert(0, file_path)

root = tk.Tk()
root.title("Password Cracker")
root.geometry("600x450")
root.resizable(False, False)

tk.Label(root, text="Enter Username:").pack(pady=5)
username_entry = tk.Entry(root, width=40)
username_entry.pack(pady=5)

tk.Label(root, text="Dictionary File:").pack(pady=5)
dictionary_file_entry = tk.Entry(root, width=40)
dictionary_file_entry.insert(0, "dictionary.txt")
dictionary_file_entry.pack(pady=5)
tk.Button(root, text="Browse", command=select_dictionary_file).pack(pady=5)

tk.Label(root, text="Select Attack Type:").pack(pady=5)
attack_type_var = tk.StringVar(value="Both")
tk.Radiobutton(root, text="Dictionary Only", variable=attack_type_var, value="Dictionary").pack()
tk.Radiobutton(root, text="Brute Force Only", variable=attack_type_var, value="Brute Force").pack()
tk.Radiobutton(root, text="Both", variable=attack_type_var, value="Both").pack()

tk.Label(root, text="Brute Force Length:").pack(pady=5)
length_entry = tk.Entry(root, width=10)
length_entry.insert(0, "5")
length_entry.pack(pady=5)

start_button = tk.Button(root, text="Start Attack", command=start_attack, bg="red", fg="white")
start_button.pack(pady=10)

output_box = scrolledtext.ScrolledText(root, width=70, height=15)
output_box.pack(pady=5)

root.mainloop()