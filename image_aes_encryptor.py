"""
Image AES Encryptor / Decryptor (single-file)

Features:
- AES symmetric encryption of image files using PyCryptodome.
- Supports ECB, CBC, CTR modes.
- Key derived from passphrase using PBKDF2-HMAC-SHA256 (configurable iterations).
- GUI built with tkinter to select files, choose mode, and encrypt/decrypt.
- Encrypted file format stores a small header with salt, IV/nonce and original filename so decryption recovers the original image file.

Dependencies:
- Python 3.8+
- pycryptodome
- pillow

Install dependencies:
    pip install pycryptodome pillow

Usage (command-line via GUI):
    python image_aes_encryptor.py

Security notes:
- ECB leaks patterns in images and is not recommended for real use — included only for academic comparison.
- Use a strong passphrase. CBC and CTR use random IV/nonce stored in the encrypted file header.

Encrypted file format (binary):
    6 bytes: magic b'IMGAES'\n    1 byte: version (1)\n    1 byte: mode_code (1=ECB,2=CBC,3=CTR)\n    16 bytes: salt for KDF\n    1 byte: iv_or_nonce_length (n)\n    n bytes: iv or nonce (if mode requires it; for ECB length = 0)\n    2 bytes: original filename length (big-endian)\n    filename bytes (utf-8)\n    rest: ciphertext bytes

"""

import os
import struct
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PIL import Image

MAGIC = b'IMGAES'
VERSION = 1
MODE_CODES = {'ECB':1, 'CBC':2, 'CTR':3}
MODE_NAMES = {v:k for k,v in MODE_CODES.items()}

# --- Crypto helpers ---
BLOCK_SIZE = 16
KDF_ITER = 200_000
KEY_LEN = 32  # AES-256
SALT_LEN = 16


def derive_key(passphrase: str, salt: bytes, iterations: int = KDF_ITER, key_len: int = KEY_LEN) -> bytes:
    """Derive a symmetric key from a passphrase and salt using PBKDF2-HMAC-SHA256."""
    if isinstance(passphrase, str):
        passphrase = passphrase.encode('utf-8')
    return PBKDF2(passphrase, salt, dkLen=key_len, count=iterations)


def encrypt_bytes(plaintext: bytes, key: bytes, mode: str):
    """Encrypt raw bytes with AES in the chosen mode. Returns (ciphertext, iv_or_nonce).
    iv_or_nonce may be b'' for ECB."""
    if mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        ct = cipher.encrypt(pad(plaintext, BLOCK_SIZE))
        return ct, b''
    elif mode == 'CBC':
        iv = get_random_bytes(BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        ct = cipher.encrypt(pad(plaintext, BLOCK_SIZE))
        return ct, iv
    elif mode == 'CTR':
        nonce = get_random_bytes(8)  # 64-bit nonce; counter used internally
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        ct = cipher.encrypt(plaintext)  # CTR doesn't need padding
        return ct, nonce
    else:
        raise ValueError('Unsupported mode')


def decrypt_bytes(ciphertext: bytes, key: bytes, mode: str, iv_or_nonce: bytes):
    if mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        pt = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
        return pt
    elif mode == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC, iv=iv_or_nonce)
        pt = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
        return pt
    elif mode == 'CTR':
        cipher = AES.new(key, AES.MODE_CTR, nonce=iv_or_nonce)
        pt = cipher.decrypt(ciphertext)
        return pt
    else:
        raise ValueError('Unsupported mode')


# --- File-level wrapper to include metadata in encrypted file ---

def encrypt_file(input_path: str, output_path: str, passphrase: str, mode: str):
    # Read file bytes (we encrypt the whole file as a blob)
    with open(input_path, 'rb') as f:
        plain = f.read()

    salt = get_random_bytes(SALT_LEN)
    key = derive_key(passphrase, salt)
    ciphertext, iv_or_nonce = encrypt_bytes(plain, key, mode)

    # Build header
    mode_code = MODE_CODES[mode]
    iv_len = len(iv_or_nonce)
    filename = os.path.basename(input_path).encode('utf-8')
    fname_len = len(filename)

    with open(output_path, 'wb') as out:
        out.write(MAGIC)
        out.write(struct.pack('B', VERSION))
        out.write(struct.pack('B', mode_code))
        out.write(salt)
        out.write(struct.pack('B', iv_len))
        if iv_len:
            out.write(iv_or_nonce)
        out.write(struct.pack('>H', fname_len))
        out.write(filename)
        out.write(ciphertext)


def decrypt_file(input_path: str, output_dir: str, passphrase: str) -> str:
    with open(input_path, 'rb') as f:
        data = f.read()

    offset = 0
    if data[offset:offset+len(MAGIC)] != MAGIC:
        raise ValueError('Not a file produced by this tool (bad magic)')
    offset += len(MAGIC)

    version = data[offset]
    offset += 1
    if version != VERSION:
        raise ValueError(f'Unsupported version: {version}')

    mode_code = data[offset]
    offset += 1
    mode = MODE_NAMES.get(mode_code)
    if not mode:
        raise ValueError('Unknown mode in file')

    salt = data[offset:offset+SALT_LEN]
    offset += SALT_LEN

    iv_len = data[offset]
    offset += 1
    iv_or_nonce = b''
    if iv_len:
        iv_or_nonce = data[offset:offset+iv_len]
        offset += iv_len

    fname_len = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    filename = data[offset:offset+fname_len].decode('utf-8')
    offset += fname_len

    ciphertext = data[offset:]

    key = derive_key(passphrase, salt)
    plaintext = decrypt_bytes(ciphertext, key, mode, iv_or_nonce)

    out_path = os.path.join(output_dir, filename)
    with open(out_path, 'wb') as f:
        f.write(plaintext)
    return out_path


# --- GUI ---
class App:
    def __init__(self, root):
        self.root = root
        root.title('Image AES Encryptor / Decryptor')
        self.mode_var = tk.StringVar(value='CBC')
        self.operation = tk.StringVar(value='Encrypt')
        self.input_path = tk.StringVar()
        self.passphrase = tk.StringVar()

        frm = ttk.Frame(root, padding=12)
        frm.grid(sticky='nsew')

        # Operation
        ttk.Label(frm, text='Operation:').grid(row=0, column=0, sticky='w')
        op_menu = ttk.OptionMenu(frm, self.operation, 'Encrypt', 'Encrypt', 'Decrypt')
        op_menu.grid(row=0, column=1, sticky='w')

        # Mode
        ttk.Label(frm, text='Mode:').grid(row=1, column=0, sticky='w')
        for i, m in enumerate(['ECB','CBC','CTR']):
            ttk.Radiobutton(frm, text=m, variable=self.mode_var, value=m).grid(row=1, column=1+i, sticky='w')

        # Input file
        ttk.Label(frm, text='File:').grid(row=2, column=0, sticky='w')
        entry = ttk.Entry(frm, textvariable=self.input_path, width=48)
        entry.grid(row=2, column=1, columnspan=2, sticky='w')
        ttk.Button(frm, text='Browse', command=self.browse_file).grid(row=2, column=3, sticky='w')

        # Passphrase
        ttk.Label(frm, text='Passphrase:').grid(row=3, column=0, sticky='w')
        ttk.Entry(frm, textvariable=self.passphrase, width=48, show='*').grid(row=3, column=1, columnspan=2, sticky='w')
        ttk.Button(frm, text='Generate', command=self.generate_passphrase).grid(row=3, column=3, sticky='w')

        # Action
        self.action_btn = ttk.Button(frm, text='Run', command=self.run_action)
        self.action_btn.grid(row=4, column=0, columnspan=4, pady=8)

        # Status
        self.status = ttk.Label(frm, text='Ready')
        self.status.grid(row=5, column=0, columnspan=4, sticky='w')

        # Make resizable
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)

    def browse_file(self):
        if self.operation.get() == 'Encrypt':
            path = filedialog.askopenfilename(title='Select image to encrypt', filetypes=[('Image files','*.png *.jpg *.jpeg *.bmp *.gif'), ('All files','*.*')])
        else:
            path = filedialog.askopenfilename(title='Select encrypted file', filetypes=[('Encrypted files','*.enc *.aes *.*')])
        if path:
            self.input_path.set(path)

    def generate_passphrase(self):
        p = get_random_bytes(12)
        # show as base64-like hex for copy-paste
        self.passphrase.set(p.hex())
        messagebox.showinfo('Passphrase generated', 'A random passphrase has been generated and placed in the passphrase field (hex).')

    def run_action(self):
        path = self.input_path.get()
        if not path or not os.path.exists(path):
            messagebox.showerror('Error', 'Please select a valid input file first')
            return
        passphrase = self.passphrase.get()
        if not passphrase:
            if not messagebox.askyesno('No passphrase', 'No passphrase entered. Continue with an empty passphrase?'):
                return

        try:
            if self.operation.get() == 'Encrypt':
                out_path = filedialog.asksaveasfilename(defaultextension='.enc', filetypes=[('Encrypted file','*.enc')], title='Save encrypted file as')
                if not out_path:
                    return
                self.status.config(text='Encrypting...')
                self.root.update_idletasks()
                encrypt_file(path, out_path, passphrase or '', self.mode_var.get())
                self.status.config(text=f'Encrypted -> {out_path}')
                messagebox.showinfo('Done', f'File encrypted and saved to:\n{out_path}')
            else:
                out_dir = filedialog.askdirectory(title='Select folder to save decrypted image')
                if not out_dir:
                    return
                self.status.config(text='Decrypting...')
                self.root.update_idletasks()
                out_path = decrypt_file(path, out_dir, passphrase or '')
                self.status.config(text=f'Decrypted -> {out_path}')
                messagebox.showinfo('Done', f'File decrypted and saved to:\n{out_path}')
        except Exception as e:
            messagebox.showerror('Error', f'Operation failed:\n{e}')
            self.status.config(text='Error')


if __name__ == '__main__':
    root = tk.Tk()
    app = App(root)
    root.mainloop()
