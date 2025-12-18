# Malware Config Extraction Suite

> **Project Type:** Offensive & Defensive Engineering  
> **Languages:** ![C](https://img.shields.io/badge/C-Language-orange) ![Python](https://img.shields.io/badge/Python-3.x-blue)  
> **Core Concepts:** Reverse Engineering, XOR Obfuscation, Static Analysis, Tool Development

---

## Project Overview
This project simulates a full-cycle malware analysis scenario. It demonstrates both **Offensive Engineering** (creating a custom C implant with obfuscated indicators) and **Defensive Engineering** (developing a Python-based automated extraction tool to defeat that obfuscation).

The goal is to demonstrate an understanding of how malware authors hide Command & Control (C2) configuration data and how security analysts reverse-engineer these techniques.

---

## Component 1: The Malware Implant (`implant.c`)
### **Adversary Role**

This C program mimics a "beacon" or "dropper" that attempts to hide its destination URL from basic static analysis tools like `strings` or antivirus scanners.

### Technical Techniques Used:
* **Stack Strings:** The configuration is not stored as a plain string but as a byte array (`unsigned char`). This prevents it from appearing in the `.rdata` section as a readable string.
* **XOR Obfuscation:** The payload is encrypted using a single-byte XOR key (`0x55`). The data is only decrypted in memory at runtime, just before the connection attempt.

**Key Code Snippet:**
```c
// The "Secret" Config (Encrypted)
unsigned char encrypted_config[] = { 
    0x3d, 0x21, 0x21, 0x25, ... 
};

// Runtime Decryption Routine
for (int i = 0; i < sizeof(encrypted_config); i++) {
    decrypted_config[i] = encrypted_config[i] ^ key;
}
```
## Component 2: The Config Extractor (config_extractor.py)

### **Analyst Role:** 

This Python tool is designed to perform "black box" analysis on the compiled binary. It assumes the analyst does not have the source code or the key, and must recover the hidden C2 URL through brute-force analysis.

### Technical Logic:

  Keyspace Exhaustion: Since single-byte XOR only has 256 possible keys (0x00 - 0xFF), the tool blindly attempts every possible key against the binary data.

  Heuristic Detection: The tool does not know the correct key, but it relies on an invariant: a C2 configuration must contain a URL. It scans every decryption attempt for the strings http:// or https://.

  Sanitization: Once the key is found, regular expressions (regex) are used to surgically extract the URL from the surrounding garbage bytes (nulls/padding).

**Key Code Snippet:**
```Python

# Try every possible key (0-255)
for key in range(256):
    decrypted = xor_decrypt(content, key)
    
    # If the result contains a URL, we found the key
    if "http://" in decrypted:
        print(f"[!] Key Found: 0x{key:02x}")
```
## How to Run
**1. Compile the Implant**

Use gcc to turn the C code into a Windows-style binary (or Linux executable).
Bash

`gcc implant.c -o implant.bin`

**2. Run the Extractor**

Point the Python tool at the compiled binary to recover the hidden secret.
Bash

`python3 config_extractor.py implant.bin`


## Skills Demonstrated

    Reverse Engineering: Understanding binary file structures and memory allocation.

    Cryptography: Implementing and breaking symmetric XOR encryption.

    Tool Development: Writing custom Python scripts to automate analysis tasks.

    C Programming: Managing memory and byte-level operations.
