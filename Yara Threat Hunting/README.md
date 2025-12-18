# Threat Hunting Rules (YARA)

> **Project Type:** Threat Intelligence & Detection Engineering
>
> **Language:** YARA
>
> **Target:** Custom XOR-Obfuscated Malware
>
> **Status:** Verified Detection

---

## Project Overview
This project focuses on **Signature Development**, a skill that is quite frankly a ***must*** for Malware Triage and Threat Intelligence roles.

Instead of relying on automated tools, I manually engineered YARA rules to detect specific indicators of compromise (IOCs) found in custom malware implants. This demonstrates the ability to translate reverse-engineering findings into actionable detection logic that can be deployed across endpoints (EDR) or network scanners.

---

## The Rule Logic (`detect_implant.yar`)

The rule targets a custom C-based implant that utilizes XOR encryption to hide its Command & Control (C2) configuration.

### Detection Strategy
The rule relies on a multi-factor condition to minimize False Positives:

1.  **File Header Analysis:**
    * Checks for `0x457f` (ELF/Linux) or `0x5a4d` (MZ/Windows) magic bytes to ensure we are only scanning executable files, not text documents.

2.  **Opcode/Byte Pattern Matching:**
    * **$encrypted_config:** Detects the specific hex byte sequence `{ 3d 21 21 25 ... }`. This corresponds to the XOR-encrypted version of the C2 URL. This is a high-fidelity indicator because this specific byte sequence is unlikely to occur in legitimate software.

3.  **String Artifacts:**
    * **$fake_message:** Detects the social engineering string *"Starting legitimate windows service"* used by the malware to trick users.

  ---
  
## **Prerequisites** 

**YARA** 

You can install YARA via `sudo pacman -S yara` on Arch Linux or follow the installation process or whichever OS you are on.

---

## Usage

Run the rule against a directory or specific file.
> You would run this if you wanted to check a specific file:
```bash

yara detect_implant.yar ./implant.bin
```
> You would run this if you wanted to check a specific directory:

```bash
yara detect_implant.yar .
```

### Expected Output

If the malware is detected, YARA will output the rule name and filename:
`Suspicious_XOR_Implant ./implant.bin`

If there is no malware detected, YARA will return nothing.

---

## Skills Demonstrated

    Signature Engineering: Creating high-fidelity rules based on static artifacts.

    Hex Analysis: Identifying unique byte sequences in compiled binaries.

    Threat Intelligence: Mapping specific malware behaviors (XOR obfuscation) to detection logic.
