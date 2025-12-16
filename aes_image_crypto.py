"""
AES Image Encryption/Decryption Application
Supports ECB, CBC, and CTR modes
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import io
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import secrets


class AESImageCrypto:
    """Handle AES encryption/decryption operations"""
    
    def __init__(self):
        self.backend = default_backend()
        self.key_size = 32  # 256-bit key
        self.block_size = 128  # AES block size in bits
    
    def generate_key(self):
        """Generate a random 256-bit AES key"""
        return secrets.token_bytes(self.key_size)
    
    def generate_iv(self):
        """Generate a random initialization vector"""
        return secrets.token_bytes(16)  # 128 bits
    
    def pad_data(self, data):
        """Pad data to AES block size using PKCS7"""
        padder = padding.PKCS7(self.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        return padded_data
    
    def unpad_data(self, data):
        """Remove PKCS7 padding"""
        unpadder = padding.PKCS7(self.block_size).unpadder()
        unpadded_data = unpadder.update(data) + unpadder.finalize()
        return unpadded_data
    
    def encrypt_ecb(self, data, key):
        """Encrypt data using AES-ECB mode"""
        padded_data = self.pad_data(data)
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext, None  # No IV for ECB
    
    def decrypt_ecb(self, ciphertext, key):
        """Decrypt data using AES-ECB mode"""
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = self.unpad_data(padded_plaintext)
        return plaintext
    
    def encrypt_cbc(self, data, key, iv=None):
        """Encrypt data using AES-CBC mode"""
        if iv is None:
            iv = self.generate_iv()
        padded_data = self.pad_data(data)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext, iv
    
    def decrypt_cbc(self, ciphertext, key, iv):
        """Decrypt data using AES-CBC mode"""
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = self.unpad_data(padded_plaintext)
        return plaintext
    
    def encrypt_ctr(self, data, key, nonce=None):
        """Encrypt data using AES-CTR mode"""
        if nonce is None:
            nonce = self.generate_iv()
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext, nonce
    
    def decrypt_ctr(self, ciphertext, key, nonce):
        """Decrypt data using AES-CTR mode"""
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=self.backend)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext


class ImageCryptoGUI:
    """GUI Application for Image Encryption/Decryption"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("AES Image Encryption/Decryption")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        self.crypto = AESImageCrypto()
        self.key = None
        self.iv = None
        self.input_image_path = None
        self.output_image_data = None
        self.last_iv_base_path = None  # Track the base path for IV file
        
        self.setup_gui()
    
    def setup_gui(self):
        """Setup the GUI components"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="AES Image Encryption/Decryption", 
                                font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, pady=10)
        
        # Operation selection
        operation_frame = ttk.LabelFrame(main_frame, text="Operation", padding="10")
        operation_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        self.operation_var = tk.StringVar(value="encrypt")
        ttk.Radiobutton(operation_frame, text="Encrypt", variable=self.operation_var, 
                       value="encrypt", command=self.update_ui).grid(row=0, column=0, padx=10)
        ttk.Radiobutton(operation_frame, text="Decrypt", variable=self.operation_var, 
                       value="decrypt", command=self.update_ui).grid(row=0, column=1, padx=10)
        
        # Mode selection
        mode_frame = ttk.LabelFrame(main_frame, text="Encryption Mode", padding="10")
        mode_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=5)
        
        self.mode_var = tk.StringVar(value="ECB")
        ttk.Radiobutton(mode_frame, text="ECB (Electronic Codebook)", 
                       variable=self.mode_var, value="ECB").grid(row=0, column=0, padx=10)
        ttk.Radiobutton(mode_frame, text="CBC (Cipher Block Chaining)", 
                       variable=self.mode_var, value="CBC").grid(row=0, column=1, padx=10)
        ttk.Radiobutton(mode_frame, text="CTR (Counter)", 
                       variable=self.mode_var, value="CTR").grid(row=0, column=2, padx=10)
        
        # Key management
        key_frame = ttk.LabelFrame(main_frame, text="Key Management", padding="10")
        key_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(key_frame, text="Generate New Key", 
                  command=self.generate_key).grid(row=0, column=0, padx=5)
        ttk.Button(key_frame, text="Load Key", 
                  command=self.load_key).grid(row=0, column=1, padx=5)
        ttk.Button(key_frame, text="Save Key", 
                  command=self.save_key).grid(row=0, column=2, padx=5)
        
        self.key_label = ttk.Label(key_frame, text="No key loaded", foreground="red")
        self.key_label.grid(row=1, column=0, columnspan=3, pady=5)
        
        # Image selection
        image_frame = ttk.LabelFrame(main_frame, text="Image Selection", padding="10")
        image_frame.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(image_frame, text="Select Input Image", 
                  command=self.select_input_image).grid(row=0, column=0, padx=5)
        self.input_label = ttk.Label(image_frame, text="No image selected")
        self.input_label.grid(row=0, column=1, padx=5, sticky=tk.W)
        
        # Process buttons
        process_frame = ttk.Frame(main_frame, padding="10")
        process_frame.grid(row=5, column=0, pady=10)
        
        self.process_button = ttk.Button(process_frame, text="Encrypt Image", 
                                        command=self.process_image, 
                                        style='Accent.TButton')
        self.process_button.grid(row=0, column=0, padx=5)
        
        ttk.Button(process_frame, text="Save Output", 
                  command=self.save_output).grid(row=0, column=1, padx=5)
        
        # Image preview
        preview_frame = ttk.LabelFrame(main_frame, text="Image Preview", padding="10")
        preview_frame.grid(row=6, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        main_frame.rowconfigure(6, weight=1)
        
        # Canvas for image display
        self.canvas = tk.Canvas(preview_frame, width=800, height=400, bg='gray90')
        self.canvas.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        preview_frame.columnconfigure(0, weight=1)
        preview_frame.rowconfigure(0, weight=1)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                              relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=7, column=0, sticky=(tk.W, tk.E), pady=5)
    
    def update_ui(self):
        """Update UI based on operation selection"""
        if self.operation_var.get() == "encrypt":
            self.process_button.config(text="Encrypt Image")
        else:
            self.process_button.config(text="Decrypt Image")
    
    def generate_key(self):
        """Generate a new encryption key"""
        self.key = self.crypto.generate_key()
        self.key_label.config(text=f"Key generated: {self.key[:8].hex()}...", 
                             foreground="green")
        self.status_var.set("New key generated successfully")
    
    def load_key(self):
        """Load encryption key from file"""
        filepath = filedialog.askopenfilename(
            title="Select Key File",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")]
        )
        if filepath:
            try:
                with open(filepath, 'rb') as f:
                    self.key = f.read()
                if len(self.key) != 32:
                    raise ValueError("Invalid key size")
                self.key_label.config(text=f"Key loaded: {self.key[:8].hex()}...", 
                                     foreground="green")
                self.status_var.set("Key loaded successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load key: {str(e)}")
    
    def save_key(self):
        """Save encryption key to file"""
        if self.key is None:
            messagebox.showwarning("Warning", "No key to save. Generate a key first.")
            return
        
        filepath = filedialog.asksaveasfilename(
            title="Save Key File",
            defaultextension=".key",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")]
        )
        if filepath:
            try:
                with open(filepath, 'wb') as f:
                    f.write(self.key)
                self.status_var.set("Key saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save key: {str(e)}")
    
    def select_input_image(self):
        """Select input image file"""
        filepath = filedialog.askopenfilename(
            title="Select Image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.gif"),
                      ("Encrypted files", "*.enc"),
                      ("All files", "*.*")]
        )
        if filepath:
            self.input_image_path = filepath
            self.input_label.config(text=os.path.basename(filepath))
            self.display_input_image()
            self.status_var.set(f"Selected: {os.path.basename(filepath)}")
    
    def display_input_image(self):
        """Display the input image on canvas"""
        if self.input_image_path:
            try:
                if self.operation_var.get() == "encrypt":
                    img = Image.open(self.input_image_path)
                    img.thumbnail((400, 400))
                    photo = ImageTk.PhotoImage(img)
                    
                    self.canvas.delete("all")
                    self.canvas.create_image(200, 200, image=photo)
                    self.canvas.image = photo
                else:
                    self.canvas.delete("all")
                    self.canvas.create_text(200, 200, 
                                          text="Encrypted file selected\n(Preview not available)",
                                          font=('Arial', 12))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to display image: {str(e)}")
    
    def process_image(self):
        """Process the image (encrypt or decrypt)"""
        if self.key is None:
            messagebox.showwarning("Warning", "Please generate or load a key first.")
            return
        
        if self.input_image_path is None:
            messagebox.showwarning("Warning", "Please select an input image first.")
            return
        
        try:
            if self.operation_var.get() == "encrypt":
                self.encrypt_image()
            else:
                self.decrypt_image()
        except Exception as e:
            messagebox.showerror("Error", f"Operation failed: {str(e)}")
    
    def encrypt_image(self):
        """Encrypt the selected image"""
        # Read image
        with open(self.input_image_path, 'rb') as f:
            image_data = f.read()
        
        # Encrypt based on mode
        mode = self.mode_var.get()
        self.status_var.set(f"Encrypting with {mode} mode...")
        self.root.update()
        
        if mode == "ECB":
            ciphertext, self.iv = self.crypto.encrypt_ecb(image_data, self.key)
        elif mode == "CBC":
            ciphertext, self.iv = self.crypto.encrypt_cbc(image_data, self.key)
        else:  # CTR
            ciphertext, self.iv = self.crypto.encrypt_ctr(image_data, self.key)
        
        # Store output
        self.output_image_data = ciphertext
        
        # Store IV path for saving later (use original filename as base)
        if self.iv and mode in ["CBC", "CTR"]:
            self.last_iv_base_path = self.input_image_path
        
        # Display result
        self.canvas.delete("all")
        self.canvas.create_text(600, 200, 
                              text=f"Image encrypted successfully!\n"
                                   f"Mode: {mode}\n"
                                   f"Size: {len(ciphertext)} bytes",
                              font=('Arial', 12), fill='green')
        
        self.status_var.set(f"Encryption completed using {mode} mode")
    
    def decrypt_image(self):
        """Decrypt the selected image"""
        # Read encrypted data
        with open(self.input_image_path, 'rb') as f:
            ciphertext = f.read()
        
        # Load IV if needed
        mode = self.mode_var.get()
        if mode in ["CBC", "CTR"]:
            # Try to find IV file - check multiple possible locations
            # If input is "image.png.enc", look for "image.png.enc.iv" first, then "image.png.iv"
            possible_iv_paths = [
                self.input_image_path + ".iv",  # e.g., image.png.enc.iv
            ]
            
            # If the encrypted file ends with .enc, also try the base name
            if self.input_image_path.endswith('.enc'):
                base_path = self.input_image_path[:-4]  # Remove .enc
                possible_iv_paths.append(base_path + ".iv")  # e.g., image.png.iv
            
            iv_path = None
            for path in possible_iv_paths:
                if os.path.exists(path):
                    iv_path = path
                    break
            
            if iv_path is None:
                messagebox.showerror("Error", 
                    f"IV file not found. Looked for:\n" + 
                    "\n".join(possible_iv_paths) +
                    f"\n\nFor {mode} mode, you need the IV file that was created during encryption.")
                return
            
            with open(iv_path, 'rb') as f:
                self.iv = f.read()
            self.status_var.set(f"Loaded IV from: {os.path.basename(iv_path)}")
        
        # Decrypt based on mode
        self.status_var.set(f"Decrypting with {mode} mode...")
        self.root.update()
        
        if mode == "ECB":
            plaintext = self.crypto.decrypt_ecb(ciphertext, self.key)
        elif mode == "CBC":
            plaintext = self.crypto.decrypt_cbc(ciphertext, self.key, self.iv)
        else:  # CTR
            plaintext = self.crypto.decrypt_ctr(ciphertext, self.key, self.iv)
        
        # Store output
        self.output_image_data = plaintext
        
        # Display decrypted image
        try:
            img = Image.open(io.BytesIO(plaintext))
            img.thumbnail((400, 400))
            photo = ImageTk.PhotoImage(img)
            
            self.canvas.delete("all")
            self.canvas.create_image(600, 200, image=photo)
            self.canvas.image = photo
            
            self.status_var.set(f"Decryption completed using {mode} mode")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to display decrypted image: {str(e)}")
    
    def save_output(self):
        """Save the processed image"""
        if self.output_image_data is None:
            messagebox.showwarning("Warning", "No output to save. Process an image first.")
            return
        
        if self.operation_var.get() == "encrypt":
            default_ext = ".enc"
            filetypes = [("Encrypted files", "*.enc"), ("All files", "*.*")]
        else:
            default_ext = ".png"
            filetypes = [("PNG files", "*.png"), ("JPEG files", "*.jpg"),
                        ("All files", "*.*")]
        
        filepath = filedialog.asksaveasfilename(
            title="Save Output",
            defaultextension=default_ext,
            filetypes=filetypes
        )
        
        if filepath:
            try:
                # Save the encrypted/decrypted data
                with open(filepath, 'wb') as f:
                    f.write(self.output_image_data)
                
                # If encrypting and we have an IV, save it with proper naming
                if self.operation_var.get() == "encrypt" and self.iv and self.mode_var.get() in ["CBC", "CTR"]:
                    # Save IV with the same base name as the encrypted file
                    iv_path = filepath + ".iv"
                    with open(iv_path, 'wb') as f:
                        f.write(self.iv)
                    self.status_var.set(f"Output saved to {os.path.basename(filepath)} (IV saved as {os.path.basename(iv_path)})")
                    messagebox.showinfo("Success", f"File saved successfully!\n\nEncrypted file: {os.path.basename(filepath)}\nIV file: {os.path.basename(iv_path)}\n\nKeep both files together for decryption!")
                else:
                    self.status_var.set(f"Output saved to {os.path.basename(filepath)}")
                    messagebox.showinfo("Success", "File saved successfully!")
                    
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")


def main():
    root = tk.Tk()
    app = ImageCryptoGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()