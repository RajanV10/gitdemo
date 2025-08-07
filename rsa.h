#ifndef RSA_H_
#define RSA_H_

#include <stddef.h>
#include <stdbool.h>
#include <mbedtls/rsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/hmac_drbg.h>
#include <mbedtls/bignum.h>

// RSA and DH Configuration
#define KEY_BITS 1024
#define EXPONENT 65537
#define DH_PRIME_HEX "C9F9D69A8C5F3D3F9A1D3DABCD45F9A75D1D"
#define DH_GENERATOR "2"

// Function prototypes
void server_crypto_init(void);
void export_public_key(mbedtls_rsa_context *rsa);
char *get_public_key_string_lazy(void);
unsigned char *server_export_pubB(size_t *olen_out);
void server_crypto_cleanup(void);
bool is_rsa_initialized(void);

// New functions for handling encrypted DH key
int server_decrypt_client_dh_key(const char *encrypted_hex, unsigned char *decrypted_buffer, size_t *decrypted_len);
int server_generate_shared_secret(const unsigned char *client_dh_pubkey, size_t client_dh_len, 
                                  unsigned char *shared_secret, size_t *secret_len);
int server_send_dh_pubkey(int sockfd);
int server_get_dh_pubkey(unsigned char *pubkey_buffer, size_t *pubkey_len);

// External global variables (defined in rsa.c)
extern mbedtls_rsa_context rsa;
extern mbedtls_entropy_context entropy;
extern mbedtls_hmac_drbg_context hmac_drbg;

#endif // RSA_H_
