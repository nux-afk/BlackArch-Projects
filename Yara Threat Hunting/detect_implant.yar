rule Suspicious_XOR_Implant {
    meta:
        author = "nux-afk"
        description = "Detects custom XOR-encrypted implant"
        severity = "High"

    strings:
        // 1. The Hex Bytes (The encrypted config)
        $encrypted_config = { 3d 21 21 25 6f 7a 7a 30 }

        // 2. The Text String (The fake message)
        // We use 'ascii' to be specific
        $fake_message = "Starting legitimate windows service" ascii

    condition:
        // Check for Linux ELF header (0x457f) OR Windows PE header (0x5a4d)
        (uint16(0) == 0x457f or uint16(0) == 0x5a4d) and
        
        // RELAXED CONDITION: Match if EITHER identifier is found
        ($encrypted_config or $fake_message)
}