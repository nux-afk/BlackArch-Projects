import sys
import re

def xor_decrypt(data, key):
    # Decrypts the data using a single-byte XOR key
    return bytearray([b ^ key for b in data])

def brute_force_xor(file_path):
    print(f"[*] Scanning {file_path} for hidden configurations...")

    try:
        with open(file_path, "rb") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[!] Error: File {file_path} not found.")
        sys.exit(1)
    
    found_something = False

    # Try very possible single-byte XOR key (0-255)
    for key in range(256):
        decrypted_data = xor_decrypt(content, key)

        try:
            result = decrypted_data.decode('utf-8', errors='ignore')
            # The Heuristic: If we see "http://" or "https://" then we found the key!
            if "http://" in result or "https://" in result:
                print(f"\n[!] POTENTIAL CONFIG FOUND!")
                print(f"    Key Used: 0x{key:02x}")
                
                # Next we need to extract the URL using regex
                urls = re.findall(r'https?://[^s\sx00]+', result)
                for url in urls:
                    print(f"    Extracted C2: {url}")

                found_something = True
        except Exception as e:
            continue

    if not found_something:
        print("[-] No obvious C2 URLs found. The malware might use a different encryption.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys/argv[0]} <file_path>")
        sys.exit(1)

    brute_force_xor(sys.argv[1])