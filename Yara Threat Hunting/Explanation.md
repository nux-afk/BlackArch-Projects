# Technical Walkthrough: YARA Threat Hunting Rule

> **Topic:** Signature-Based Detection
> 
> **Target:** XOR-Obfuscated Malware Implant
> 
> **Tool:** YARA (Yet Another Recursive Acronym)

---

## What is this script?
This file (`detect_implant.yar`) is a **YARA Rule**. YARA is the industry-standard tool used by malware researchers to identify and classify malware samples based on textual or binary patterns.

While an antivirus might just say "File is malicious," YARA allows analysts to ask specific questions like: *"Does this file contain this specific encryption key?"* or *"Does this file contain this specific fake error message?"*

In this project, I wrote a custom rule to detect the **C implant** I created in the previous step, specifically targeting the artifacts left behind by my custom XOR obfuscation.

---

## The Code Explained

Here is the complete rule used in the project, followed by a line-by-line breakdown of why it works.

```yara
rule Suspicious_XOR_Implant {
    meta:
        author = "nux-afk"
        description = "Detects custom XOR-encrypted implant"
        severity = "High"

    strings:
        $encrypted_config = { 3d 21 21 25 6f 7a 7a 30 }
        $fake_message = "Starting legitimate windows service" ascii
    condition:
        (uint16(0) == 0x457f or uint16(0) == 0x5a4d) and
        ($encrypted_config or $fake_message)
}
```
## 1. The meta Section
Code Snippet

```yara
    meta:
        author = "nux-afk"
        severity = "High"
```

This section is purely for the human analyst. It doesn't affect detection. It provides context on who wrote the rule and how dangerous the match is. Ideally, in a real Security Operations Center (SOC), this metadata helps prioritize alerts.

## 2. The strings Section (The "Fingerprints")

This is where we define what we are looking for.
```yara
    $encrypted_config = { 3d 21 21 25 ... }
```

What it is: A Hexadecimal string search.

Why we use it: The malware stores its C2 URL (http://...) as an encrypted byte array to hide it. I extracted these exact bytes from the C source code. This is a high-fidelity indicator because normal software will almost never have this exact random sequence of bytes.

```yara
    $fake_message = "Starting..." ascii
```

What it is: A plain text ASCII string search.

Why we use it: The malware prints a misleading message to the console to trick users. Malware often contains typos or specific phrasing ("social engineering") that can be used to track it.

## 3. The Condition Section or "Logic"

This is the boolean logic that determines if the rule matches or fails.
```yara
    uint16(0) == 0x457f or uint16(0) == 0x5a4d
```
Translation: "Read the first 16 bits (2 bytes) of the file. Is it 0x457f (Linux ELF) OR 0x5a4d (Windows EXE)?"

Purpose: Just for optimization. We sure as hell don't want to waste CPU power scanning text files, images, or PDFs. We only want to scan executable programs.

```yara
    ($encrypted_config or $fake_message)
```

Translation: "Does the file contain the secret hex bytes OR the fake text message?"

Purpose: Compilers such as GCC optimize code and might mangle one of our indicators. By using OR, we can be sure that if any trace of the malware survives compilation, we can catch it.
        
## How to Run It

To test this rule against a directory of files:
```bash

# Syntax: yara [rule_file] [target_directory]
yara detect_implant.yar .
```

If the malware (implant.bin) is present, YARA will output: 

`Suspicious_XOR_Implant ./implant.bin`

---

### Thank You For Reading
That's everything! I hope this technical document helped understand the script a bit if you had any trouble! 
