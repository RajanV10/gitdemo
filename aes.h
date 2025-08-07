#ifndef AES_H_
#define AES_H_

#include <stdint.h>
#include <stddef.h>

// AES block size is always 16 bytes
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 16  // AES-128

// Function prototypes
int aes_module_init(void);
int aes_module_encrypt(const uint8_t *input, size_t input_len, uint8_t *output, size_t *output_len, const uint8_t *key);
int aes_module_decrypt(const uint8_t *input, size_t input_len, uint8_t *output, size_t *output_len, const uint8_t *key);
void aes_module_deinit(void);

#endif // AES_H_
