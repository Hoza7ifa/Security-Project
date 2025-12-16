# AES Image Encryption/Decryption Application

## Project Overview
This application implements AES (Advanced Encryption Standard) image encryption and decryption with support for three encryption modes: ECB, CBC, and CTR. It provides a user-friendly GUI interface for secure image processing.

## Features
- ✅ AES-256 encryption/decryption
- ✅ Three encryption modes: ECB, CBC, CTR
- ✅ GUI interface with Tkinter
- ✅ Key generation and management
- ✅ Image preview
- ✅ Support for multiple image formats (PNG, JPG, BMP, GIF)

## Requirements

### Python Version
- Python 3.7 or higher

### Required Libraries
```bash
pip install cryptography pillow
```

Or install all at once:
```bash
pip install -r requirements.txt
```

### requirements.txt
```
cryptography>=41.0.0
pillow>=10.0.0
```

## Installation

1. **Clone or download the project files**
   ```bash
   # Create project directory
   mkdir aes_image_crypto
   cd aes_image_crypto
   ```

2. **Save the main application file as `image_crypto.py`**

3. **Install dependencies**
   ```bash
   pip install cryptography pillow
   ```

4. **Run the application**
   ```bash
   python image_crypto.py
   ```

## Usage Guide

### 1. Generate or Load Encryption Key

**Generate New Key:**
- Click "Generate New Key" button
- The key will be displayed (first 8 bytes shown)
- Save the key for later use by clicking "Save Key"

**Load Existing Key:**
- Click "Load Key" button
- Select a previously saved `.key` file

⚠️ **Important:** Keep your encryption key safe! Without it, you cannot decrypt your images.

### 2. Encrypting an Image

1. Select "Encrypt" operation mode
2. Choose encryption mode (ECB, CBC, or CTR)
3. Generate or load an encryption key
4. Click "Select Input Image" and choose your image
5. Click "Encrypt Image" button
6. Click "Save Output" to save the encrypted file (`.enc` extension)

**Note:** For CBC and CTR modes, an IV (Initialization Vector) file will be automatically saved with `.iv` extension.

### 3. Decrypting an Image

1. Select "Decrypt" operation mode
2. Choose the same encryption mode used for encryption
3. Load the encryption key used for encryption
4. Click "Select Input Image" and choose the `.enc` file
5. Click "Decrypt Image" button
6. The decrypted image will be displayed in the preview
7. Click "Save Output" to save the recovered image

## Encryption Modes Explained

### ECB (Electronic Codebook)
- **How it works:** Each block is encrypted independently
- **Pros:** Simple, parallel processing
- **Cons:** Identical plaintext blocks produce identical ciphertext (less secure)
- **Best for:** Educational purposes, understanding block ciphers
- **Security Note:** Not recommended for images with patterns

### CBC (Cipher Block Chaining)
- **How it works:** Each block depends on the previous block using an IV
- **Pros:** More secure than ECB, blocks are chained
- **Cons:** Sequential processing, requires IV
- **Best for:** General-purpose encryption
- **Security Note:** Recommended for most use cases

### CTR (Counter Mode)
- **How it works:** Converts block cipher into stream cipher using counter
- **Pros:** Parallel processing, no padding needed, high security
- **Cons:** Requires unique nonce for each encryption
- **Best for:** High-performance applications
- **Security Note:** Very secure when implemented correctly

## Testing the System

### Test Case 1: Basic Encryption/Decryption (ECB)
1. Generate a new key and save it as `test_key_ecb.key`
2. Select a test image (e.g., `test_image.png`)
3. Choose ECB mode
4. Encrypt the image and save as `encrypted_ecb.enc`
5. Decrypt `encrypted_ecb.enc` using the same key
6. Save the decrypted image as `recovered_ecb.png`
7. Compare original and recovered images

**Expected Result:** Recovered image should be identical to the original

### Test Case 2: CBC Mode with IV
1. Generate a new key and save it as `test_key_cbc.key`
2. Select a test image
3. Choose CBC mode
4. Encrypt and save as `encrypted_cbc.enc`
5. Note that `encrypted_cbc.enc.iv` is also created
6. Decrypt using the same key and IV
7. Save recovered image

**Expected Result:** Successful decryption with IV file

### Test Case 3: CTR Mode
1. Generate a new key and save it as `test_key_ctr.key`
2. Select a test image
3. Choose CTR mode
4. Encrypt and save as `encrypted_ctr.enc`
5. Decrypt using the same key and nonce
6. Compare results

**Expected Result:** Perfect recovery of original image

### Test Case 4: Different Image Formats
Test with various formats:
- PNG (lossless)
- JPG (lossy)
- BMP (uncompressed)
- GIF (indexed color)

**Expected Result:** All formats should encrypt/decrypt successfully

### Test Case 5: Large Images
1. Test with high-resolution images (e.g., 4K, 8K)
2. Measure encryption/decryption time
3. Verify memory usage

**Expected Result:** System handles large files efficiently

### Test Case 6: Wrong Key Test
1. Encrypt an image with one key
2. Attempt to decrypt with a different key
3. Observe the result

**Expected Result:** Decryption fails or produces garbage data

### Test Case 7: Visual Security Comparison
1. Encrypt a patterned image (e.g., checkerboard) with all three modes
2. Open encrypted files in hex editor or image viewer
3. Compare which mode reveals patterns

**Expected Result:** ECB may show patterns, CBC and CTR should not

## File Structure

```
aes_image_crypto/
│
├── image_crypto.py          # Main application
├── requirements.txt          # Python dependencies
├── README.md                # This file
│
├── keys/                    # Store encryption keys (create this folder)
│   ├── test_key_ecb.key
│   ├── test_key_cbc.key
│   └── test_key_ctr.key
│
├── test_images/             # Original test images
│   ├── test1.png
│   ├── test2.jpg
│   └── test3.bmp
│
├── encrypted/               # Encrypted files
│   ├── encrypted_ecb.enc
│   ├── encrypted_cbc.enc
│   ├── encrypted_cbc.enc.iv
│   ├── encrypted_ctr.enc
│   └── encrypted_ctr.enc.iv
│
└── recovered/               # Decrypted/recovered images
    ├── recovered_ecb.png
    ├── recovered_cbc.png
    └── recovered_ctr.png
```

## Technical Details

### AES Implementation
- **Algorithm:** AES (Advanced Encryption Standard)
- **Key Size:** 256 bits (32 bytes)
- **Block Size:** 128 bits (16 bytes)
- **Padding:** PKCS7 (for ECB and CBC modes)
- **Library:** Python `cryptography` package

### Security Considerations
1. **Key Storage:** Never hardcode keys in source code
2. **Key Transmission:** Use secure channels to share keys
3. **IV/Nonce:** Must be unique for each encryption with CBC/CTR
4. **Mode Selection:** Use CBC or CTR for production, avoid ECB
5. **Key Management:** Store keys securely, consider key rotation

## Troubleshooting

### Error: "No module named 'cryptography'"
**Solution:** Install the cryptography library
```bash
pip install cryptography
```

### Error: "No module named 'PIL'"
**Solution:** Install Pillow
```bash
pip install pillow
```

### Error: "IV file not found"
**Solution:** Ensure the `.iv` file is in the same directory as the `.enc` file for CBC/CTR modes

### Error: "Invalid key size"
**Solution:** Ensure you're using a valid 256-bit (32-byte) AES key

### Decrypted image is corrupted
**Possible causes:**
- Wrong encryption key used
- Wrong encryption mode selected
- Missing or incorrect IV file
- Original encrypted file was modified

## Advanced Features to Add (Optional Enhancements)

1. **Password-based encryption:** Derive keys from passwords using PBKDF2
2. **Batch processing:** Encrypt/decrypt multiple images at once
3. **Compression:** Compress images before encryption
4. **Metadata preservation:** Keep EXIF data intact
5. **Performance metrics:** Show encryption/decryption speed
6. **Image comparison:** Built-in diff tool for before/after
7. **Secure deletion:** Overwrite original files after encryption

## Team Collaboration Guidelines

### Division of Work (5 team members)

1. **Member 1:** Core encryption library implementation (AESImageCrypto class)
2. **Member 2:** GUI design and layout (ImageCryptoGUI class structure)
3. **Member 3:** Key management features (generate, save, load)
4. **Member 4:** Image processing and preview functionality
5. **Member 5:** Testing, documentation, and bug fixes

### Version Control
Use Git for collaboration:
```bash
git init
git add .
git commit -m "Initial commit: AES image encryption application"
```

## License
This project is for educational purposes. Ensure compliance with local encryption regulations.

## Contributors
[Add team member names here]

## References
- [NIST AES Specification](https://csrc.nist.gov/publications/detail/fips/197/final)
- [Python Cryptography Documentation](https://cryptography.io/)
- [AES Encryption Modes](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)

---
**Last Updated:** October 2025
**Version:** 1.0.0
