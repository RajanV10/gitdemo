#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/net/socket.h>
#include <mbedtls/bignum.h>
#include <mbedtls/rsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/hmac_drbg.h>
#include <mbedtls/md.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "rsa.h"

#define KEY_BITS 1024
#define EXPONENT 65537
#define DH_PRIME_HEX "C9F9D69A8C5F3D3F9A1D3DABCD45F9A75D1D" // Example prime
#define DH_GENERATOR "2"

mbedtls_rsa_context rsa;
mbedtls_entropy_context entropy;
mbedtls_hmac_drbg_context hmac_drbg;
mbedtls_mpi p, g, y, pubB;  // DH components

// RSA initialization flag
static bool rsa_initialized = false;

// Forward declaration
static char *get_public_key_string(mbedtls_rsa_context *rsa);

// Function to check if RSA is initialized
bool is_rsa_initialized(void) {
    return rsa_initialized;
}

// Function to get RSA public key with lazy initialization
char *get_public_key_string_lazy(void) {
    // Initialize RSA if not already done
    if (!rsa_initialized) {
        printk("RSA not initialized. Initializing RSA cryptography on demand...\r\n");
        server_crypto_init();
    }
    
    return get_public_key_string(&rsa);
}

// Function to export RSA public key components for easy copying
void export_public_key(mbedtls_rsa_context *rsa) {
    unsigned char *n_buf = k_malloc(128);
    unsigned char *e_buf = k_malloc(8);
    size_t n_len, e_len;
    mbedtls_mpi N, E;
    
    if (!n_buf || !e_buf) {
        printk("Failed to allocate memory for key export\n");
        if (n_buf) k_free(n_buf);
        if (e_buf) k_free(e_buf);
        return;
    }
    
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&E);
    
    // Export modulus (N)
    if (mbedtls_rsa_export(rsa, &N, NULL, NULL, NULL, &E) == 0) {
        if (mbedtls_mpi_write_binary(&N, n_buf, 128) == 0) {
            n_len = mbedtls_mpi_size(&N);
            printk("=== MODULUS (N) FOR DECRYPTION PROGRAM ===\n");
            printk("uint8_t n_bytes[128] = {\n    ");
            for (int i = 0; i < n_len; i++) {
                printk("0x%02x", n_buf[i]);
                if (i < n_len - 1) printk(", ");
                if ((i + 1) % 16 == 0 && i < n_len - 1) printk("\n    ");
            }
            printk("\n};\n\n");
        }
        
        // Export public exponent (E) - should be 65537
        // Get the actual size first, then write binary with correct size
        e_len = mbedtls_mpi_size(&E);
        if (mbedtls_mpi_write_binary(&E, e_buf, e_len) == 0) {
            printk("=== PUBLIC EXPONENT (E) FOR DECRYPTION PROGRAM ===\n");
            printk("uint8_t e_bytes[%zu] = {\n    ", e_len);
            for (int i = 0; i < e_len; i++) {
                printk("0x%02x", e_buf[i]);
                if (i < e_len - 1) printk(", ");
            }
            printk("\n};\n");
            printk("// E = %d (0x10001)\n\n", EXPONENT);
        }
    }
    
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&E);
    k_free(n_buf);
    k_free(e_buf);
}

// Function to get RSA public key as a formatted string for client transmission
static char *get_public_key_string(mbedtls_rsa_context *rsa) {
    static char key_string[2048]; // Static buffer for the key string
    unsigned char *n_buf = k_malloc(128);
    unsigned char *e_buf = k_malloc(8);
    size_t n_len, e_len;
    mbedtls_mpi N, E;
    int offset = 0;
    
    if (!n_buf || !e_buf) {
        if (n_buf) k_free(n_buf);
        if (e_buf) k_free(e_buf);
        snprintf(key_string, sizeof(key_string), "ERROR: Failed to allocate memory for key export\r\n");
        return key_string;
    }
    
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&E);
    
    // Start building the key string
    offset += snprintf(key_string + offset, sizeof(key_string) - offset, 
                      "=== RSA PUBLIC KEY ===\r\n");
    offset += snprintf(key_string + offset, sizeof(key_string) - offset,
                      "Key Size: %d bits\r\n", KEY_BITS);
    offset += snprintf(key_string + offset, sizeof(key_string) - offset,
                      "Public Exponent: %d\r\n\r\n", EXPONENT);
    
    // Export modulus (N) and exponent (E)
    if (mbedtls_rsa_export(rsa, &N, NULL, NULL, NULL, &E) == 0) {
        if (mbedtls_mpi_write_binary(&N, n_buf, 128) == 0) {
            n_len = mbedtls_mpi_size(&N);
            offset += snprintf(key_string + offset, sizeof(key_string) - offset,
                              "Modulus (N) [%zu bytes]:\r\n", n_len);
            
            for (int i = 0; i < n_len && offset < sizeof(key_string) - 10; i++) {
                if (i % 16 == 0) {
                    offset += snprintf(key_string + offset, sizeof(key_string) - offset, "  ");
                }
                offset += snprintf(key_string + offset, sizeof(key_string) - offset, "%02x", n_buf[i]);
                if (i < n_len - 1) {
                    offset += snprintf(key_string + offset, sizeof(key_string) - offset, " ");
                }
                if ((i + 1) % 16 == 0) {
                    offset += snprintf(key_string + offset, sizeof(key_string) - offset, "\r\n");
                }
            }
            if (n_len % 16 != 0) {
                offset += snprintf(key_string + offset, sizeof(key_string) - offset, "\r\n");
            }
        }
        
        // Get the actual size first, then write binary with correct size
        e_len = mbedtls_mpi_size(&E);
        if (mbedtls_mpi_write_binary(&E, e_buf, e_len) == 0) {
            offset += snprintf(key_string + offset, sizeof(key_string) - offset,
                              "\r\nPublic Exponent (E) [%zu bytes]:\r\n  ", e_len);
            
            for (int i = 0; i < e_len && offset < sizeof(key_string) - 10; i++) {
                offset += snprintf(key_string + offset, sizeof(key_string) - offset, "%02x", e_buf[i]);
                if (i < e_len - 1) {
                    offset += snprintf(key_string + offset, sizeof(key_string) - offset, " ");
                }
            }
            offset += snprintf(key_string + offset, sizeof(key_string) - offset, "\r\n");
        }
    } else {
        offset += snprintf(key_string + offset, sizeof(key_string) - offset,
                          "ERROR: Failed to export RSA key components\r\n");
    }
    
    offset += snprintf(key_string + offset, sizeof(key_string) - offset,
                      "\r\n=== END PUBLIC KEY ===\r\n");
    
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&E);
    k_free(n_buf);
    k_free(e_buf);
    
    return key_string;
}

void server_crypto_init()
{
    // Prevent double initialization
    if (rsa_initialized) {
        printk("RSA already initialized, skipping...\r\n");
        return;
    }
    
    // This is done in main.c file and i pass it here
    mbedtls_rsa_init(&rsa);
    mbedtls_entropy_init(&entropy);
    mbedtls_hmac_drbg_init(&hmac_drbg);
    mbedtls_mpi_init(&p); mbedtls_mpi_init(&g);
    mbedtls_mpi_init(&y); mbedtls_mpi_init(&pubB);

    uint8_t seed[32] = {0}; // deterministic seed for testing
    
    if (mbedtls_hmac_drbg_seed_buf(&hmac_drbg, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), seed, sizeof(seed)) != 0) {
        printk("Failed to seed HMAC-DRBG\r\n");
        return;
    }

    if (mbedtls_rsa_gen_key(&rsa, mbedtls_hmac_drbg_random, &hmac_drbg, KEY_BITS, EXPONENT) != 0) {
        printk("Failed to generate RSA key\r\n");
        return;
    }

    // Export key components after generation
    printk("RSA Key Generated Successfully!\r\n");
    export_public_key(&rsa);
    
    // Mark as initialized
    rsa_initialized = true;
}

unsigned char *server_export_pubB(size_t *olen_out)
{
    mbedtls_mpi_read_string(&p, 16, DH_PRIME_HEX);
    mbedtls_mpi_read_string(&g, 10, DH_GENERATOR);

    mbedtls_mpi_fill_random(&y, 32, mbedtls_hmac_drbg_random, &hmac_drbg);
    mbedtls_mpi_exp_mod(&pubB, &g, &y, &p, NULL);  // pubB = g^y mod p
    
    size_t len = mbedtls_mpi_size(&pubB);
    unsigned char *buf = k_malloc(len);
    if (!buf) return NULL;

    mbedtls_mpi_write_binary(&pubB, buf, len);
    *olen_out = len;
    return buf;
}
void server_crypto_cleanup()
{
    if (rsa_initialized) {
        mbedtls_rsa_free(&rsa);
        mbedtls_entropy_free(&entropy);
        mbedtls_hmac_drbg_free(&hmac_drbg);
        mbedtls_mpi_free(&p); mbedtls_mpi_free(&g);
        mbedtls_mpi_free(&y); mbedtls_mpi_free(&pubB);
        rsa_initialized = false;
        printk("RSA cryptography cleaned up\r\n");
    }
}

// Function to decrypt client's encrypted DH public key
int server_decrypt_client_dh_key(const char *encrypted_hex, unsigned char *decrypted_buffer, size_t *decrypted_len) {
    printk("Decrypting client's DH public key...\n");
    
    // Ensure RSA is initialized
    if (!rsa_initialized) {
        printk("ERROR: RSA not initialized\n");
        return -1;
    }
    
    // Convert hex string to binary
    size_t hex_len = strlen(encrypted_hex);
    if (hex_len != 256) { // RSA 1024-bit = 128 bytes = 256 hex chars
        printk("ERROR: Invalid encrypted data length: %zu (expected 256)\n", hex_len);
        return -1;
    }
    
    unsigned char encrypted_data[128];
    char hex_pair[3] = {0};
    
    for (int i = 0; i < 128; i++) {
        hex_pair[0] = encrypted_hex[i * 2];
        hex_pair[1] = encrypted_hex[i * 2 + 1];
        hex_pair[2] = '\0';
        encrypted_data[i] = (unsigned char)strtol(hex_pair, NULL, 16);
    }
    
    printk("Converted hex to binary (128 bytes)\n");
    
    // Set RSA padding mode to PKCS#1 v1.5 (same as client)
    mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
    
    // Decrypt using RSA private key
    int ret = mbedtls_rsa_pkcs1_decrypt(&rsa, mbedtls_hmac_drbg_random, &hmac_drbg,
                                       decrypted_len, encrypted_data, decrypted_buffer, *decrypted_len);
    if (ret != 0) {
        printk("ERROR: RSA decryption failed: -0x%x\n", -ret);
        return ret;
    }
    
    printk("Successfully decrypted client DH public key (%zu bytes)\n", *decrypted_len);
    
    // Print decrypted DH key for verification
    printk("Decrypted DH public key (hex): ");
    for (size_t i = 0; i < *decrypted_len; i++) {
        printk("%02x", decrypted_buffer[i]);
    }
    printk("\n");
    
    return 0;
}

// Function to generate shared secret using client's DH public key
int server_generate_shared_secret(const unsigned char *client_dh_pubkey, size_t client_dh_len, 
                                  unsigned char *shared_secret, size_t *secret_len) {
    printk("Generating DH shared secret...\n");
    
    // Ensure RSA/DH is initialized
    if (!rsa_initialized) {
        printk("ERROR: Crypto not initialized\n");
        return -1;
    }
    
    // Import client's DH public key
    mbedtls_mpi client_pubA;
    mbedtls_mpi shared_key;
    mbedtls_mpi_init(&client_pubA);
    mbedtls_mpi_init(&shared_key);
    
    int ret = mbedtls_mpi_read_binary(&client_pubA, client_dh_pubkey, client_dh_len);
    if (ret != 0) {
        printk("ERROR: Failed to import client DH public key: -0x%x\n", -ret);
        mbedtls_mpi_free(&client_pubA);
        mbedtls_mpi_free(&shared_key);
        return ret;
    }
    
    printk("Imported client DH public key\n");
    
    // Ensure we have our DH parameters initialized
    if (mbedtls_mpi_cmp_int(&p, 0) == 0) {
        // Initialize DH parameters if not done yet
        ret = mbedtls_mpi_read_string(&p, 16, DH_PRIME_HEX);
        if (ret != 0) {
            printk("ERROR: Failed to set DH prime: -0x%x\n", -ret);
            mbedtls_mpi_free(&client_pubA);
            mbedtls_mpi_free(&shared_key);
            return ret;
        }
        
        ret = mbedtls_mpi_read_string(&g, 10, DH_GENERATOR);
        if (ret != 0) {
            printk("ERROR: Failed to set DH generator: -0x%x\n", -ret);
            mbedtls_mpi_free(&client_pubA);
            mbedtls_mpi_free(&shared_key);
            return ret;
        }
        
        // Generate our private key if not done yet
        if (mbedtls_mpi_cmp_int(&y, 0) == 0) {
            ret = mbedtls_mpi_fill_random(&y, 32, mbedtls_hmac_drbg_random, &hmac_drbg);
            if (ret != 0) {
                printk("ERROR: Failed to generate server DH private key: -0x%x\n", -ret);
                mbedtls_mpi_free(&client_pubA);
                mbedtls_mpi_free(&shared_key);
                return ret;
            }
            printk("Generated new server DH private key\n");
        } else {
            printk("Using existing server DH private key\n");
        }
        
        printk("Initialized server DH parameters\n");
    }
    
    // Calculate shared secret: shared_key = client_pubA^y mod p
    ret = mbedtls_mpi_exp_mod(&shared_key, &client_pubA, &y, &p, NULL);
    if (ret != 0) {
        printk("ERROR: Failed to calculate shared secret: -0x%x\n", -ret);
        mbedtls_mpi_free(&client_pubA);
        mbedtls_mpi_free(&shared_key);
        return ret;
    }
    
    // Export shared secret to buffer
    size_t required_len = mbedtls_mpi_size(&shared_key);
    if (required_len > *secret_len) {
        printk("ERROR: Buffer too small for shared secret (need %zu, have %zu)\n", required_len, *secret_len);
        mbedtls_mpi_free(&client_pubA);
        mbedtls_mpi_free(&shared_key);
        return -1;
    }
    
    ret = mbedtls_mpi_write_binary(&shared_key, shared_secret, required_len);
    if (ret != 0) {
        printk("ERROR: Failed to export shared secret: -0x%x\n", -ret);
        mbedtls_mpi_free(&client_pubA);
        mbedtls_mpi_free(&shared_key);
        return ret;
    }
    
    *secret_len = required_len;
    
    printk("Successfully generated DH shared secret (%zu bytes)\n", *secret_len);
    printk("Shared secret (hex): ");
    for (size_t i = 0; i < *secret_len; i++) {
        printk("%02x", shared_secret[i]);
    }
    printk("\n");
    
    mbedtls_mpi_free(&client_pubA);
    mbedtls_mpi_free(&shared_key);
    return 0;
}

// Function to get server's DH public key
int server_get_dh_pubkey(unsigned char *pubkey_buffer, size_t *pubkey_len) {
    printk("Generating server DH public key...\n");
    
    // Ensure RSA/DH is initialized
    if (!rsa_initialized) {
        printk("ERROR: Crypto not initialized\n");
        return -1;
    }
    
    // Initialize DH parameters if not done yet
    if (mbedtls_mpi_cmp_int(&p, 0) == 0) {
        int ret = mbedtls_mpi_read_string(&p, 16, DH_PRIME_HEX);
        if (ret != 0) {
            printk("ERROR: Failed to set DH prime: -0x%x\n", -ret);
            return ret;
        }
        
        ret = mbedtls_mpi_read_string(&g, 10, DH_GENERATOR);
        if (ret != 0) {
            printk("ERROR: Failed to set DH generator: -0x%x\n", -ret);
            return ret;
        }
        
        printk("DH parameters set successfully\n");
    }
    
    // Always check if we need to generate the server's DH key pair
    if (mbedtls_mpi_cmp_int(&y, 0) == 0 || mbedtls_mpi_cmp_int(&pubB, 0) == 0) {
        // Generate our private key
        int ret = mbedtls_mpi_fill_random(&y, 32, mbedtls_hmac_drbg_random, &hmac_drbg);
        if (ret != 0) {
            printk("ERROR: Failed to generate server DH private key: -0x%x\n", -ret);
            return ret;
        }
        
        // Calculate our public key: pubB = g^y mod p
        ret = mbedtls_mpi_exp_mod(&pubB, &g, &y, &p, NULL);
        if (ret != 0) {
            printk("ERROR: Failed to calculate server DH public key: -0x%x\n", -ret);
            return ret;
        }
        
        printk("Generated server DH key pair\n");
    }
    
    // Export public key to buffer
    size_t required_len = mbedtls_mpi_size(&pubB);
    if (required_len == 0) {
        printk("ERROR: Server DH public key has zero size\n");
        return -1;
    }
    
    if (required_len > *pubkey_len) {
        printk("ERROR: Buffer too small for DH public key (need %zu, have %zu)\n", required_len, *pubkey_len);
        return -1;
    }
    
    int ret = mbedtls_mpi_write_binary(&pubB, pubkey_buffer, required_len);
    if (ret != 0) {
        printk("ERROR: Failed to export DH public key: -0x%x\n", -ret);
        return ret;
    }
    
    *pubkey_len = required_len;
    printk("Server DH public key exported (%zu bytes)\n", *pubkey_len);
    
    // Debug: print the key
    printk("Server DH public key (hex): ");
    for (size_t i = 0; i < *pubkey_len; i++) {
        printk("%02x", pubkey_buffer[i]);
    }
    printk("\n");
    
    return 0;
}

// Function to send server's DH public key to client
int server_send_dh_pubkey(int sockfd) {
    printk("Sending server DH public key to client...\n");
    
    unsigned char dh_pubkey[256];
    size_t dh_pubkey_len = sizeof(dh_pubkey);
    
    // Get our DH public key
    int ret = server_get_dh_pubkey(dh_pubkey, &dh_pubkey_len);
    if (ret != 0) {
        printk("ERROR: Failed to get server DH public key: %d\n", ret);
        return ret;
    }
    
    // Format message to send to client
    char message[1024];
    int offset = 0;
    
    // Add header
    offset += snprintf(message + offset, sizeof(message) - offset, "SERVER_DH_PUBKEY:");
    
    // Add DH public key as hex
    for (size_t i = 0; i < dh_pubkey_len && offset < sizeof(message) - 3; i++) {
        offset += snprintf(message + offset, sizeof(message) - offset, "%02x", dh_pubkey[i]);
    }
    
    // Add terminators
    offset += snprintf(message + offset, sizeof(message) - offset, "\r\n");
    
    // Send to client using Zephyr socket API
    int sent = zsock_send(sockfd, message, offset, 0);
    if (sent < 0) {
        printk("ERROR: Failed to send server DH public key\n");
        return -1;
    }
    
    printk("Sent server DH public key to client (%d bytes)\n", sent);
    printk("Server DH public key (hex): ");
    for (size_t i = 0; i < dh_pubkey_len; i++) {
        printk("%02x", dh_pubkey[i]);
    }
    printk("\n");
    
    return 0;
}
