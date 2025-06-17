/*
 * Charybdis Block Cipher - Header File
 * 
 * Author: Mounir IDRASSI <mounir.idrassi@amcrypto.jp>
 * Version: 1.0
 * Date: June 15, 2025
 * 
 * This header file defines the public API for the Charybdis symmetric-key block cipher.
 * 
 * ALGORITHM PARAMETERS:
 *   - Block size: 512 bits (64 bytes)
 *   - Key size: 256 bits (32 bytes)
 *   - Structure: Substitution-Permutation Network (SPN)
 *   - Rounds: 22
 *   - Internal state: 4x4 matrix of 32-bit words
 *   - Subkeys: 24 subkeys of 512 bits each
 * 
 * SECURITY FEATURES:
 *   - ARX-based non-linear layer for side-channel resistance
 *   - Full-state constant injection for structural attack resistance
 *   - Sponge-based key schedule with 1024-bit internal state
 *   - All constants derived transparently from SHAKE256
 * 
 * SPECIFICATION:
 *   For the complete algorithm specification, see "Charybdis-v1-spec.md"
 * 
 * LICENSE:
 *   CC0 1.0 Universal (Public Domain Dedication)
 *   This work is dedicated to the public domain.
 *   https://creativecommons.org/publicdomain/zero/1.0/
 * 
 * DISCLAIMER:
 *   This is a reference implementation intended for educational and research
 *   purposes. It has not been optimized for performance or hardened against
 *   side-channel attacks. Production use should employ additional protections.
 */

#ifndef CHARYBDIS_H
#define CHARYBDIS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =============================================================================
 * ALGORITHM CONSTANTS
 * ============================================================================= */

/* Block and key sizes in bytes */
#define CHARYBDIS_BLOCK_SIZE    64      /* 512 bits */
#define CHARYBDIS_KEY_SIZE      32      /* 256 bits */

/* Internal parameters */
#define CHARYBDIS_ROUNDS        22      /* Number of main rounds */
#define CHARYBDIS_SUBKEYS       24      /* Number of subkeys (K[0] to K[23]) */
#define CHARYBDIS_STATE_WORDS   16      /* 4x4 matrix of 32-bit words */

#define CHARYBDIS_RC_COUNT      (CHARYBDIS_ROUNDS * 16) /* Total number of round constants (22 rounds * 16 words per round) */

/* Key schedule parameters */
#define CHARYBDIS_KS_STATE_SIZE 128     /* 1024 bits = 4x8 matrix of 32-bit words */
#define CHARYBDIS_KS_ROUNDS     16      /* Number of F_perm rounds */

/* =============================================================================
 * DATA TYPES
 * ============================================================================= */

/**
 * @brief Charybdis cipher context structure
 * 
 * This structure holds the expanded subkeys for encryption/decryption operations.
 * After calling KeySchedule(), this context can be used for multiple 
 * encrypt/decrypt operations with the same key.
 */
typedef struct {
    uint32_t subkeys[CHARYBDIS_SUBKEYS][4][4];  /**< Expanded subkeys */
} charybdis_context_t;

/* =============================================================================
 * PUBLIC API FUNCTIONS
 * ============================================================================= */

/**
 * @brief Guaranteed secure memory clearing
 *
 * Uses platform-specific secure memory clearing functions
 */

#ifdef _WIN32
#define charybdis_secure_memzero(ptr,len) SecureZeroMemory(ptr, len)
#elif defined(HAVE_EXPLICIT_BZERO)
#define charybdis_secure_memzero(ptr,len) explicit_bzero(ptr, len);
#elif defined(HAVE_MEMSET_S)
#define charybdis_secure_memzero(ptr,len) memset_s(ptr, len, 0, len);
#else
#define charybdis_secure_memzero(ptr,len) do { \
        volatile uint8_t* p = (volatile uint8_t*)ptr; \
        size_t i; \
        for (i = 0; i < len; i++) { \
            p[i] = 0; \
        } \
        /* LTO barrier to prevent optimization */
        __asm__ __volatile__("" : : "r"(ptr) : "memory"); \
} while (0);
#endif

/**
 * @brief Generate subkeys from master key
 * 
 * Expands a 256-bit master key into 24 subkeys of 512 bits each using the
 * Charybdis key schedule. The key schedule uses a sponge construction with
 * a 1024-bit internal state and a 16-round permutation.
 * 
 * @param[in]  master_key  256-bit master key (32 bytes, little-endian)
 * @param[out] subkeys     Array to store 24 expanded subkeys
 * 
 * @pre master_key must point to a valid 32-byte array
 * @pre subkeys must point to a valid array of 24 4x4 uint32_t matrices
 * 
 * @note All multi-byte values are processed in little-endian byte order
 * @note This function must be called before encryption/decryption
 */
void Charybdis_KeySchedule(const uint8_t master_key[CHARYBDIS_KEY_SIZE], 
                 uint32_t subkeys[CHARYBDIS_SUBKEYS][4][4]);

/**
 * @brief Encrypt a single 512-bit block
 * 
 * Encrypts one 64-byte plaintext block using the Charybdis cipher with
 * pre-computed subkeys. The encryption process includes:
 * 1. Initial whitening with K[0]
 * 2. 22 main rounds with K[1] through K[22]
 * 3. Final whitening with K[23]
 * 
 * @param[in]  in       64-byte plaintext block (little-endian)
 * @param[out] out      64-byte ciphertext block (little-endian)
 * @param[in]  subkeys  Pre-computed subkeys from KeySchedule()
 * 
 * @pre in must point to a valid 64-byte array
 * @pre out must point to a valid 64-byte array
 * @pre subkeys must contain valid subkeys from KeySchedule()
 * 
 * @note Input and output buffers may be the same (in-place encryption)
 * @note All data is processed in little-endian byte order
 */
void Charybdis_EncryptBlock(const uint8_t in[CHARYBDIS_BLOCK_SIZE], 
                           uint8_t out[CHARYBDIS_BLOCK_SIZE],
                           const uint32_t subkeys[CHARYBDIS_SUBKEYS][4][4]);

/**
 * @brief Decrypt a single 512-bit block
 * 
 * Decrypts one 64-byte ciphertext block using the Charybdis cipher with
 * pre-computed subkeys. The decryption process is the inverse of encryption:
 * 1. Initial state setup with K[23]
 * 2. 22 inverse rounds with K[22] through K[1]
 * 3. Final whitening with K[0]
 * 
 * @param[in]  in       64-byte ciphertext block (little-endian)
 * @param[out] out      64-byte plaintext block (little-endian)
 * @param[in]  subkeys  Pre-computed subkeys from KeySchedule()
 * 
 * @pre in must point to a valid 64-byte array
 * @pre out must point to a valid 64-byte array
 * @pre subkeys must contain valid subkeys from KeySchedule()
 * 
 * @note Input and output buffers may be the same (in-place decryption)
 * @note All data is processed in little-endian byte order
 */
void Charybdis_DecryptBlock(const uint8_t in[CHARYBDIS_BLOCK_SIZE], 
                           uint8_t out[CHARYBDIS_BLOCK_SIZE],
                           const uint32_t subkeys[CHARYBDIS_SUBKEYS][4][4]);

/* =============================================================================
 * CONVENIENCE API
 * ============================================================================= */

/**
 * @brief Initialize Charybdis context with a master key
 * 
 * Convenience function that combines key expansion into a context structure.
 * This simplifies the API for applications that prefer context-based usage.
 * 
 * @param[out] ctx        Charybdis context to initialize
 * @param[in]  master_key 256-bit master key (32 bytes, little-endian)
 * 
 * @return 0 on success, non-zero on failure
 * 
 * @pre ctx must point to a valid charybdis_context_t structure
 * @pre master_key must point to a valid 32-byte array
 */
static inline int charybdis_init(charybdis_context_t* ctx, 
                                const uint8_t master_key[CHARYBDIS_KEY_SIZE]) {
    if (!ctx || !master_key) return -1;
    Charybdis_KeySchedule(master_key, ctx->subkeys);
    return 0;
}

/**
 * @brief Encrypt a block using a context
 * 
 * @param[in]  ctx  Initialized Charybdis context
 * @param[in]  in   64-byte plaintext block
 * @param[out] out  64-byte ciphertext block
 * 
 * @return 0 on success, non-zero on failure
 */
static inline int charybdis_encrypt(const charybdis_context_t* ctx,
                                   const uint8_t in[CHARYBDIS_BLOCK_SIZE],
                                   uint8_t out[CHARYBDIS_BLOCK_SIZE]) {
    if (!ctx || !in || !out) return -1;
    Charybdis_EncryptBlock(in, out, ctx->subkeys);
    return 0;
}

/**
 * @brief Decrypt a block using a context
 * 
 * @param[in]  ctx  Initialized Charybdis context
 * @param[in]  in   64-byte ciphertext block
 * @param[out] out  64-byte plaintext block
 * 
 * @return 0 on success, non-zero on failure
 */
static inline int charybdis_decrypt(const charybdis_context_t* ctx,
                                   const uint8_t in[CHARYBDIS_BLOCK_SIZE],
                                   uint8_t out[CHARYBDIS_BLOCK_SIZE]) {
    if (!ctx || !in || !out) return -1;
    Charybdis_DecryptBlock(in, out, ctx->subkeys);
    return 0;
}

/**
 * @brief Clear sensitive data from context
 * 
 * Securely clears the subkeys from the context structure to prevent
 * key material from remaining in memory.
 * 
 * @param[in,out] ctx  Context to clear
 */
void charybdis_clear(charybdis_context_t* ctx);

/* =============================================================================
 * VERSION INFORMATION
 * ============================================================================= */

/**
 * @brief Get algorithm version string
 * @return Version string "1.0"
 */
static inline const char* charybdis_version(void) {
    return "1.0";
}

/**
 * @brief Get algorithm name
 * @return Algorithm name "Charybdis"
 */
static inline const char* charybdis_name(void) {
    return "Charybdis";
}

/**
 * @brief Get block size in bytes
 * @return Block size (64 bytes)
 */
static inline int charybdis_block_size(void) {
    return CHARYBDIS_BLOCK_SIZE;
}

/**
 * @brief Get key size in bytes
 * @return Key size (32 bytes)
 */
static inline int charybdis_key_size(void) {
    return CHARYBDIS_KEY_SIZE;
}

#ifdef __cplusplus
}
#endif

#endif /* CHARYBDIS_H */
