#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// This is the "secret" config that malware tries to hide.
// It is the XOR encoded version of "http://evil-c2.com" using key 0x55
unsigned char encrypted_config[] = { 
    0x3d, 0x21, 0x21, 0x25, 0x6f, 0x7a, 0x7a, 0x30, 
    0x23, 0x3c, 0x39, 0x78, 0x36, 0x67, 0x7b, 0x36, 
    0x3a, 0x38, 0x00 
};

void connection_routine() {
    char decrypted_config[20];
    int key = 0x55; // The XOR key
    
    // Decryption Routine (Malware usually does this in memory)
    for (int i = 0; i < sizeof(encrypted_config); i++) {
        decrypted_config[i] = encrypted_config[i] ^ key;
    }
    
    printf("[*] Connecting to C2 Server: %s\n", decrypted_config);
    // In real malware, this would be a socket connection
}

int main() {
    printf("Starting legitimate windows service...\n");
    connection_routine();
    return 0;
}