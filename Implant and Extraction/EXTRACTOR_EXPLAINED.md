## Obfuscation Breaker

### Overview

A two-part project demonstrating **Offensive Engineering** (creating a custom C implant) and **Defensive Engineering** (writing a Python brute-force decryptor). This tool breaks XOR-based obfuscation to reveal hidden C2 configurations. This md explains `config_extractor.py` as well as the purpose of the `C implant` file to whoever reads this!

### Code Breakdown & Technical Logic

#### 1. The Malware Simulation (C Implant)

* **Code:**
```C
unsigned char encrypted_config[] = { 
    0x3d, 0x21, 0x21, 0x25, 0x6f, 0x7a, 0x7a, 0x30 
};
// ... inside connection_routine ...
for (int i = 0; i < sizeof(encrypted_config); i++) {
    decrypted_config[i] = encrypted_config[i] ^ key;
}
```
* **Concept:** Payload Obfuscation & Stack Strings.
* **Why it matters:** This demonstrates how malware hides sensitive data. By storing the Configuration as a byte array (unsigned char) instead of a string, tools like strings or basic antivirus scanners cannot see the URL. The data is only "revealed" (decrypted) for a split second in memory when the program runs.

```python
def xor_decrypt(data, key):
    # List comprehension for byte-wise XOR
    return bytearray([b ^ key for b in data])
```

* **Concept:** **Symmetric Encryption / Obfuscation**.
* **Logic:** XOR is reversible. If `A ^ B = C`, then `C ^ B = A`. By trying every possible B (key), we eventually turn C (ciphertext) back into A (plaintext).
* **Why it matters:** This is the most common lightweight obfuscation technique used by malware families (like Cobalt Strike beacons) to hide their config from basic antivirus scanners.

#### 2. The Brute-Force Loop

**Code:**

```python
def brute_force_xor(file_path):
    try:
        with open(file_path, "rb") as f:
            content = f.read()
    except FileNotFoundError:
        sys.exit(1)

    # Try every possible single-byte XOR key (0-255)
    for key in range(256):
        decrypted_data = xor_decrypt(content, key)

```

* **Concept:** **Keyspace Exhaustion**.
* **Logic:** A single byte only has 256 possible values (`0x00` - `0xFF`). Modern CPUs can try all 256 combinations effectively instantly. Since that's the case, we don't necesarrily have to be smart and use cryptanalysis, we just need to be fast with brute-forcing. 

#### 3. Heuristic Detection & Error Handling

**Code:**

```python
        try:
            # 'errors=ignore' prevents crashing on non-text bytes
            result = decrypted_data.decode('utf-8', errors='ignore')
            
            # THE HEURISTIC: If we see "http://" or "https://", we found the key!
            if "http://" in result or "https://" in result:
                print(f"    Key Used: 0x{key:02x}")

```

* **Concept:** **Pattern-Based Detection**.
* **The Logic:** We don't know the key, but we know the *structure* of the secret. A C2 server *must* have a URL scheme. We use this invariant as our success condition.
* **Error Handling:** The `errors='ignore'` flag is critical. Most incorrect keys will produce garbage bytes that aren't valid UTF-8. Without this, the script would crash on the first wrong guess.

#### 4. The Clean-Up (Regex)

**Code:**

```python
                # Looks for http/https followed by non-whitespace chars
                urls = re.findall(r'https?://[^\s\x00]+', result)
                for url in urls:
                    print(f"    Extracted C2: {url}")

```

* **Concept:** **Data Sanitization**.
* **Why it matters:** The decryption process often leaves garbage bytes around the secret. This regex extracts the clean URL for reporting and trashes the rest.

#### That's everything! I hope you understand the scripts a bit better now.