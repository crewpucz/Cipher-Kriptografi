import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

# Vigenere Cipher Enkripsi
def vigenere_encrypt(plaintext, key):
    ciphertext = ""
    key = key.upper()
    plaintext = plaintext.upper()

    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    plaintext_int = [ord(i) for i in plaintext]
    for i in range(len(plaintext_int)):
        if plaintext[i].isalpha():
            value = (plaintext_int[i] + key_as_int[i % key_length]) % 26
            ciphertext += chr(value + 65)
        else:
            ciphertext += plaintext[i]
    return ciphertext

# Vigenere Cipher Dekripsi
def vigenere_decrypt(ciphertext, key):
    plaintext = ""
    key = key.upper()
    ciphertext = ciphertext.upper()

    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    ciphertext_int = [ord(i) for i in ciphertext]
    for i in range(len(ciphertext_int)):
        if ciphertext[i].isalpha():
            value = (ciphertext_int[i] - key_as_int[i % key_length]) % 26
            plaintext += chr(value + 65)
        else:
            plaintext += ciphertext[i]
    return plaintext

# Playfair Cipher Enkripsi
def generate_playfair_key_matrix(key):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    key = key.upper().replace("J", "I")
    key_matrix = []
    used_chars = []

    for char in key:
        if char not in used_chars and char in alphabet:
            key_matrix.append(char)
            used_chars.append(char)

    for char in alphabet:
        if char not in used_chars:
            key_matrix.append(char)

    matrix = [key_matrix[i:i+5] for i in range(0, 25, 5)]
    return matrix

def find_position(char, matrix):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    return None

def playfair_encrypt(plaintext, key):
    plaintext = plaintext.upper().replace("J", "I")
    matrix = generate_playfair_key_matrix(key)
    
    # Preprocess plaintext: insert filler 'X' between repeated letters
    prepared_text = ""
    i = 0
    while i < len(plaintext):
        prepared_text += plaintext[i]
        if i + 1 < len(plaintext) and plaintext[i] == plaintext[i + 1]:
            prepared_text += 'X'  # Add filler if repeated letters
        if i + 1 < len(plaintext):
            prepared_text += plaintext[i + 1]
        i += 2

    # Add 'X' if odd length
    if len(prepared_text) % 2 != 0:
        prepared_text += 'X'

    ciphertext = ""
    for i in range(0, len(prepared_text), 2):
        a, b = prepared_text[i], prepared_text[i + 1]
        row_a, col_a = find_position(a, matrix)
        row_b, col_b = find_position(b, matrix)

        # Same row, shift right
        if row_a == row_b:
            ciphertext += matrix[row_a][(col_a + 1) % 5]
            ciphertext += matrix[row_b][(col_b + 1) % 5]
        # Same column, shift down
        elif col_a == col_b:
            ciphertext += matrix[(row_a + 1) % 5][col_a]
            ciphertext += matrix[(row_b + 1) % 5][col_b]
        # Rectangle swap
        else:
            ciphertext += matrix[row_a][col_b]
            ciphertext += matrix[row_b][col_a]

    return ciphertext

# Playfair Cipher Dekripsi
def playfair_decrypt(ciphertext, key):
    ciphertext = ciphertext.upper()
    matrix = generate_playfair_key_matrix(key)

    plaintext = ""
    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i], ciphertext[i + 1]
        row_a, col_a = find_position(a, matrix)
        row_b, col_b = find_position(b, matrix)

        # Same row, shift left
        if row_a == row_b:
            plaintext += matrix[row_a][(col_a - 1) % 5]
            plaintext += matrix[row_b][(col_b - 1) % 5]
        # Same column, shift up
        elif col_a == col_b:
            plaintext += matrix[(row_a - 1) % 5][col_a]
            plaintext += matrix[(row_b - 1) % 5][col_b]
        # Rectangle swap
        else:
            plaintext += matrix[row_a][col_b]
            plaintext += matrix[row_b][col_a]

    return plaintext

# Hill Cipher
def mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

def determinant(matrix):
    return (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % 26

def inverse_matrix(matrix):
    det = determinant(matrix)
    inv_det = mod_inverse(det, 26)

    if inv_det is None:
        return None  # Mengembalikan None jika tidak ada invers
    
    # Adjugate matrix
    adjugate = [
        [matrix[1][1], -matrix[0][1]],
        [-matrix[1][0], matrix[0][0]]
    ]
    
    # Apply mod 26 and multiply by inverse determinant
    inv_matrix = [
        [(inv_det * adjugate[0][0]) % 26, (inv_det * adjugate[0][1]) % 26],
        [(inv_det * adjugate[1][0]) % 26, (inv_det * adjugate[1][1]) % 26]
    ]
    
    return inv_matrix

def generate_hill_key_matrix(key):
    if len(key) != 4:
        raise ValueError("Hill Cipher requires a 4-character key for 2x2 matrix")
    
    key_matrix = []
    for i in range(2):
        row = [ord(key[2 * i + j].upper()) - 65 for j in range(2)]
        key_matrix.append(row)
    
    return key_matrix

def hill_encrypt(plaintext, key):
    plaintext = plaintext.upper().replace(" ", "")
    if len(plaintext) % 2 != 0:
        plaintext += 'X'  # Add filler if odd number of characters

    plaintext_nums = [ord(c) - 65 for c in plaintext]
    
    ciphertext = ""
    for i in range(0, len(plaintext_nums), 2):
        pair = plaintext_nums[i:i + 2]
        encrypted_pair = [
            (key[0][0] * pair[0] + key[0][1] * pair[1]) % 26,
            (key[1][0] * pair[0] + key[1][1] * pair[1]) % 26
        ]
        ciphertext += chr(encrypted_pair[0] + 65) + chr(encrypted_pair[1] + 65)
    
    return ciphertext

def hill_decrypt(ciphertext, key):
    ciphertext = ciphertext.upper().replace(" ", "")
    ciphertext_nums = [ord(c) - 65 for c in ciphertext]
    
    inv_key = inverse_matrix(key)
    
    if inv_key is None:
        return "Determinant tidak memiliki invers modulo 26."  # Pesan error jika tidak ada invers
    
    plaintext = ""
    for i in range(0, len(ciphertext_nums), 2):
        pair = ciphertext_nums[i:i + 2]
        decrypted_pair = [
            (inv_key[0][0] * pair[0] + inv_key[0][1] * pair[1]) % 26,
            (inv_key[1][0] * pair[0] + inv_key[1][1] * pair[1]) % 26
        ]
        plaintext += chr(decrypted_pair[0] + 65) + chr(decrypted_pair[1] + 65)
    
    return plaintext

# Upload file
def upload_file():
    filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if filepath:
        with open(filepath, 'r') as file:
            content = file.read()
            text_input.delete(1.0, tk.END)
            text_input.insert(tk.END, content)

# Fungsi untuk enkripsi/dekripsi
def process_cipher(action):
    text = text_input.get(1.0, tk.END).strip()
    key = key_entry.get().strip()

    if len(key) < 12:
        messagebox.showerror("Error", "Kunci minimal 12 karakter")
        return

    cipher = cipher_choice.get()

    if cipher == "Vigenere":
        if action == "Encrypt":
            result = vigenere_encrypt(text, key)
        else:
            result = vigenere_decrypt(text, key)
    elif cipher == "Playfair":
        if action == "Encrypt":
            result = playfair_encrypt(text, key)
        else:
            result = playfair_decrypt(text, key)
    elif cipher == "Hill":
        key_matrix = generate_hill_key_matrix(key[:4])
        if action == "Encrypt":
            result = hill_encrypt(text, key_matrix)
        else:
            result = hill_decrypt(text, key_matrix)
    else:
        result = "Cipher belum diimplementasikan"
    
    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, result)

# Membuat antarmuka GUI
app = tk.Tk()
app.title("Cipher Enkripsi & Dekripsi")
app.geometry("600x400")

# Frame untuk input teks
input_frame = tk.Frame(app)
input_frame.pack(pady=10)

tk.Label(input_frame, text="Input Teks atau Unggah File").grid(row=0, column=0, padx=5, pady=5)
text_input = ScrolledText(input_frame, width=50, height=10)
text_input.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
upload_button = tk.Button(input_frame, text="Unggah File", command=upload_file)
upload_button.grid(row=0, column=1, padx=5)

# Frame untuk input kunci dan pilihan cipher
key_frame = tk.Frame(app)
key_frame.pack(pady=10)

tk.Label(key_frame, text="Masukkan Kunci:").grid(row=0, column=0, padx=5)
key_entry = tk.Entry(key_frame, width=30)
key_entry.grid(row=0, column=1, padx=5)

tk.Label(key_frame, text="Pilih Cipher:").grid(row=1, column=0, padx=5)
cipher_choice = tk.StringVar(value="Vigenere")
cipher_menu = tk.OptionMenu(key_frame, cipher_choice, "Vigenere", "Playfair", "Hill")
cipher_menu.grid(row=1, column=1, padx=5)

# Frame untuk tombol Enkripsi dan Dekripsi
action_frame = tk.Frame(app)
action_frame.pack(pady=10)

encrypt_button = tk.Button(action_frame, text="Enkripsi", command=lambda: process_cipher("Encrypt"))
encrypt_button.grid(row=0, column=0, padx=10)

decrypt_button = tk.Button(action_frame, text="Dekripsi", command=lambda: process_cipher("Decrypt"))
decrypt_button.grid(row=0, column=1, padx=10)

# Frame untuk output hasil
output_frame = tk.Frame(app)
output_frame.pack(pady=10)

tk.Label(output_frame, text="Output:").grid(row=0, column=0, padx=5)
text_output = ScrolledText(output_frame, width=50, height=10)
text_output.grid(row=1, column=0, padx=5)

app.mainloop()
