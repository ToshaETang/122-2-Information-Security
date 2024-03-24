#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>

#define KEY_LEN 16 // 128 bits
#define IV_LEN 16  // 128 bits
#define PLAINTEXT_LEN 16 // 128 bits

// Known plaintext, ciphertext, and IV
const unsigned char plaintext[PLAINTEXT_LEN] = {0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x35, 0x0a, 0x25, 0xd0, 0xd4, 0xc5, 0xd8, 0x0a, 0x34};
const unsigned char ciphertext[PLAINTEXT_LEN] = {0xd0, 0x6b, 0xf9, 0xd0, 0xda, 0xb8, 0xe8, 0xef, 0x88, 0x06, 0x60, 0xd2, 0xaf, 0x65, 0xaa, 0x82};
const unsigned char iv[IV_LEN] = {0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0xa2, 0xb2, 0xc2, 0xd2, 0xe2, 0xf2};

// Function to decrypt with a given key
int decrypt(const unsigned char *key) {
    EVP_CIPHER_CTX *ctx;
    int len;
    unsigned char plaintext_buf[PLAINTEXT_LEN + EVP_MAX_BLOCK_LENGTH]; // Increase buffer size to accommodate maximum block length
    
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext_buf, &len, ciphertext, PLAINTEXT_LEN);
    EVP_DecryptFinal_ex(ctx, plaintext_buf + len, &len); // Correctly handle remaining ciphertext
    EVP_CIPHER_CTX_free(ctx);

    // Check if decrypted plaintext matches the known plaintext
    return memcmp(plaintext_buf, plaintext, PLAINTEXT_LEN) == 0;
}

int main() {
    time_t file_creation_time = 1524020929; // Timestamp of file creation: 2018-04-17 23:08:49
    time_t start_time = file_creation_time - 2 * 3600; // Two hours before file creation time

    printf("Start brute-force attack to find the key...\n");

    int key_found = 0; // Flag to indicate if key is found

    // Iterate over possible timestamps within the two-hour window
    for (time_t timestamp = start_time; timestamp <= file_creation_time && !key_found; timestamp++) {
        srand(timestamp);

        // Generate a key
        unsigned char key[KEY_LEN];
        for (int i = 0; i < KEY_LEN; i++) {
            key[i] = rand() % 256;
        }

        // Attempt decryption with the generated key
        if (decrypt(key)) {
            printf("Key found!\n");
            printf("Timestamp: %lld\n", (long long)timestamp);
            printf("Key: ");
            for (int i = 0; i < KEY_LEN; i++) {
                printf("%.2x", key[i]);
            }
            printf("\n");

            key_found = 1; // Set flag to true
        }
    }

    if (!key_found) {
        printf("Key not found.\n");
    }

    return 0;
}

