#include <string.h>
#include <errno.h>
#include <zephyr/kernel.h>
#include <mbedtls/aes.h>

#include "aes.h"

// Global AES context
static mbedtls_aes_context aes_ctx;
static bool aes_initialized = false;

/**
 * Initialize AES module
 * @return 0 on success, negative error code on failure
 */
int aes_module_init(void)
{
    if (aes_initialized) {
        return 0; // Already initialized
    }

    mbedtls_aes_init(&aes_ctx);
    aes_initialized = true;
    
    printk("AES: Module initialized\r\n");
    return 0;
}

/**
 * Encrypt data using AES-128 CTR mode
 * @param input Input data to encrypt
 * @param input_len Length of input data
 * @param output Output buffer for encrypted data (must be large enough)
 * @param output_len Pointer to store the actual output length
 * @param key 16-byte AES key
 * @return 0 on success, negative error code on failure
 */
int aes_module_encrypt(const uint8_t *input, size_t input_len, uint8_t *output, size_t *output_len, const uint8_t *key)
{
    int ret;
    
    if (!aes_initialized) {
        printk("AES: Module not initialized\r\n");
        return -EINVAL;
    }
    
    if (!input || !output || !output_len || !key || input_len == 0) {
        printk("AES: Invalid parameters\r\n");
        return -EINVAL;
    }

    // Limit input size to prevent memory issues
    if (input_len > 128) {  // Reduced from 256
        printk("AES: Input too large (max 128 bytes)\r\n");
        return -EINVAL;
    }

    // CTR mode variables
    uint8_t nonce_counter[AES_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    uint8_t stream_block[AES_BLOCK_SIZE];
    size_t nc_off = 0;
    
    // Set encryption key
    ret = mbedtls_aes_setkey_enc(&aes_ctx, key, AES_KEY_SIZE * 8);
    if (ret != 0) {
        printk("AES: Failed to set encryption key: -0x%04x\r\n", -ret);
        return -EINVAL;
    }
    
    // Encrypt using CTR mode
    ret = mbedtls_aes_crypt_ctr(&aes_ctx, input_len, &nc_off, nonce_counter, 
                                stream_block, input, output);
    if (ret != 0) {
        printk("AES: Failed to encrypt data: -0x%04x\r\n", -ret);
        return -EINVAL;
    }
    
    *output_len = input_len;  // CTR mode output length equals input length
    
    printk("AES: Encrypted %zu bytes\r\n", input_len);
    return 0;
}

/**
 * Decrypt data using AES-128 CTR mode
 * @param input Input encrypted data
 * @param input_len Length of input data
 * @param output Output buffer for decrypted data (must be large enough)
 * @param output_len Pointer to store the actual output length
 * @param key 16-byte AES key
 * @return 0 on success, negative error code on failure
 */
int aes_module_decrypt(const uint8_t *input, size_t input_len, uint8_t *output, size_t *output_len, const uint8_t *key)
{
    int ret;
    
    if (!aes_initialized) {
        printk("AES: Module not initialized\r\n");
        return -EINVAL;
    }
    
    if (!input || !output || !output_len || !key || input_len == 0) {
        printk("AES: Invalid parameters\r\n");
        return -EINVAL;
    }

    // Limit input size to prevent memory issues
    if (input_len > 128) {  // Reduced from 256
        printk("AES: Input too large (max 128 bytes)\r\n");
        return -EINVAL;
    }

    // CTR mode variables (same as encryption)
    uint8_t nonce_counter[AES_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    uint8_t stream_block[AES_BLOCK_SIZE];
    size_t nc_off = 0;
    
    // Set encryption key (CTR mode uses encryption for both encrypt and decrypt)
    ret = mbedtls_aes_setkey_enc(&aes_ctx, key, AES_KEY_SIZE * 8);
    if (ret != 0) {
        printk("AES: Failed to set encryption key: -0x%04x\r\n", -ret);
        return -EINVAL;
    }
    
    // Decrypt using CTR mode (same function as encryption)
    ret = mbedtls_aes_crypt_ctr(&aes_ctx, input_len, &nc_off, nonce_counter, 
                                stream_block, input, output);
    if (ret != 0) {
        printk("AES: Failed to decrypt data: -0x%04x\r\n", -ret);
        return -EINVAL;
    }
    
    *output_len = input_len;  // CTR mode output length equals input length
    
    printk("AES: Decrypted %zu bytes\r\n", input_len);
    return 0;
}

/**
 * Deinitialize AES module
 */
void aes_module_deinit(void)
{
    if (aes_initialized) {
        mbedtls_aes_free(&aes_ctx);
        aes_initialized = false;
        printk("AES: Module deinitialized\r\n");
    }
}
