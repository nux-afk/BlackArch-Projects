import hashlib
import sys
import os
import re
import pefile

def get_hashes(file_path):
    """
    Calculates MD5 and SHA256 hashes.
    Why: These are the 'fingerprints' of malware. We use them to query 
    Threat Intelligence databases like VirusTotal.
    """
    try:
        data = open(file_path, 'rb').read()
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        return md5, sha256
    except Exception as e:
        print(f"[!] Error calculating hashes: {e}")
        return None, None

def extract_strings(file_path, min_length=5):
    """
    Extracts ASCII strings from the binary.
    Why: Malware often contains hardcoded IP addresses (C2 servers),
    filenames, or messages. This is the quickest way to find IOCs.
    """
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        # Regex to find printable ASCII strings
        result = ""
        for s in re.findall(b"[\x20-\x7e]{" + str(min_length).encode() + b",}", data):
            decoded = s.decode()
            # simple filter for potential IPs or URLs
            if "http" in decoded or re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", decoded):
                result += f"    [+] Suspicious String: {decoded}\n"
        return result
    except Exception as e:
        return f"[!] Error extracting strings: {e}"

def analyze_pe(file_path):
    """
    Analyzes Windows PE headers using pefile.
    Why: We need to see if the file is 'packed' (high entropy) or 
    when it was compiled.
    """
    try:
        pe = pefile.PE(file_path)
        output = f"    [i] Compile Time: {pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value']}\n"
        
        # Check sections for high entropy (sign of packing)
        output += "    [i] Sections:\n"
        for section in pe.sections:
            output += f"        - {section.Name.decode().strip(chr(0))}: Size={section.SizeOfRawData}\n"
            
        return output
    except pefile.PEFormatError:
        return "    [-] Not a Windows PE file (Skipping PE analysis)."
    except Exception as e:
        return f"[!] PE Analysis Error: {e}"

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <file_path>")
        sys.exit(1)

    target_file = sys.argv[1]
    
    if not os.path.exists(target_file):
        print(f"[!] File not found: {target_file}")
        sys.exit(1)

    print(f"\n[*] Starting Triage on: {target_file}")
    print("=" * 60)

    # 1. Hashing
    print("[*] Calculating Hashes...")
    md5, sha256 = get_hashes(target_file)
    print(f"    MD5:    {md5}")
    print(f"    SHA256: {sha256}")

    # 2. PE Analysis
    print("\n[*] Analyzing PE Headers...")
    print(analyze_pe(target_file))

    # 3. String Extraction (IOC Hunting)
    print("\n[*] Extracting Interesting Strings...")
    print(extract_strings(target_file))
    
    print("=" * 60)
    print("[*] Triage Complete.")

if __name__ == "__main__":
    main()