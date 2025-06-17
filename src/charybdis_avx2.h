/*
 * Charybdis Block Cipher - AVX2 Optimized Implementation
 *
 * Author: Mounir IDRASSI <mounir.idrassi@amcrypto.jp>
 * Version: 1.0
 * Date: June 15, 2025
 *
 * This is the reference implementation of the Charybdis symmetric-key block cipher.
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

#ifndef CHARYBDIS_AVX2_H
#define CHARYBDIS_AVX2_H

#include "charybdis.h"
#include <immintrin.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =============================================================================
 * AVX2 OPTIMIZED CONSTANTS
 * ============================================================================= */

#define CHARYBDIS_AVX2_LANES 8                           /* AVX2 vector width in 32-bit lanes */
#define CHARYBDIS_AVX2_PARALLEL_BLOCKS CHARYBDIS_AVX2_LANES /* Process 8 blocks in parallel */
#define CHARYBDIS_AVX2_ISA_TAG 0x41565832  /* "AVX2" */

/* Portable alignment - fallback for older compilers */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
    #define ALIGNAS(n) alignas(n)
#elif defined(__GNUC__) || defined(__clang__)
    #define ALIGNAS(n) __attribute__((aligned(n)))
#elif defined(_MSC_VER)
    #define ALIGNAS(n) __declspec(align(n))
#else
    #define ALIGNAS(n)
#endif

#define ALIGN32 ALIGNAS(32) /* 32-byte alignment for AVX2 */
/* =============================================================================
 * AVX2 OPTIMIZED TYPES
 * ============================================================================= */

/**
 * @brief AVX2-optimized context with pre-vectorized subkeys and constants
 * 
 * This structure contains all data needed for high-performance AVX2 encryption.
 * Pre-vectorized subkeys and round constants eliminate broadcast overhead during
 * the hot loop. Scalar subkeys are cached for efficient tail processing.
 * 
 */
typedef struct ALIGN32 {
    /** Pre-vectorized subkeys */
    ALIGN32 __m256i vec_subkeys[CHARYBDIS_SUBKEYS][4][4];
    
    /** Pre-vectorized round constants for rounds 1-22 */
    ALIGN32 __m256i vec_round_constants[CHARYBDIS_ROUNDS][4][4];
    
    /** Cached scalar subkeys for tail processing */
    uint32_t scalar_subkeys[CHARYBDIS_SUBKEYS][4][4];
    
    /** ISA compatibility tag for additional safety */
    uint32_t isa_tag;
    
    /** Context validity marker - changes with struct size */
    uint32_t initialized;
} charybdis_avx2_context_t;

/* =============================================================================
 * AVX2 CAPABILITY DETECTION
 * ============================================================================= */

/**
 * @brief Check if AVX2 is available and enabled on this system
 * 
 * Performs comprehensive AVX2 availability check:
 * 1. CPUID feature detection (CPU supports AVX2)
 * 2. OS support verification (YMM registers saved/restored)
 * 
 * @return 1 if AVX2 is fully available, 0 otherwise
 */
int charybdis_avx2_available(void);

/* =============================================================================
 * AVX2 CONTEXT MANAGEMENT
 * ============================================================================= */

/**
 * @brief Initialize AVX2 context from scalar subkeys
 * 
 * Expands scalar subkeys into vectorized format and pre-computes round constants.
 * This is a one-time cost that enables efficient processing of multiple blocks.
 * 
 * @param[out] ctx     AVX2 context to initialize (must be aligned)
 * @param[in]  subkeys Scalar subkeys from Charybdis_KeySchedule()
 * 
 * @return 0 on success, -1 on failure (null pointers)
 * 
 * @note Context must be cleared with charybdis_avx2_clear_context() after use
 * @note This function is relatively expensive (~1000 cycles) but amortized over many blocks
 */
int charybdis_avx2_init_context(charybdis_avx2_context_t* ctx,
                                const uint32_t subkeys[CHARYBDIS_SUBKEYS][4][4]);

/**
 * @brief Clear AVX2 context securely
 * 
 * Performs guaranteed secure clearing of all key material in the context.
 * Also clears YMM registers to prevent key leakage through register state.
 * 
 * @param[in,out] ctx Context to clear (may be NULL)
 * 
 * @note Uses platform-specific secure memory clearing functions
 * @note Safe to call multiple times or with NULL pointer
 */
void charybdis_avx2_clear_context(charybdis_avx2_context_t* ctx);

/* =============================================================================
 * AVX2 BULK ENCRYPTION/DECRYPTION
 * ============================================================================= */

/**
 * @brief Encrypt multiple 64-byte blocks using AVX2
 * 
 * Processes blocks in groups of 8 using SIMD parallelism. Remaining blocks
 * (when nblocks % 8 != 0) are processed using the scalar implementation.
 * 
 * Automatic fallback for tail blocks with no performance penalty
 * 
 * @param[in]  in       Input plaintext blocks (64 * nblocks bytes)
 * @param[out] out      Output ciphertext blocks (64 * nblocks bytes)  
 * @param[in]  nblocks  Number of 64-byte blocks to encrypt
 * @param[in]  ctx      Initialized AVX2 context
 * 
 * @pre in must point to nblocks * 64 bytes of readable memory
 * @pre out must point to nblocks * 64 bytes of writable memory
 * @pre ctx must be initialized with charybdis_avx2_init_context()
 * @pre nblocks > 0
 * 
 * @note in and out may be the same (in-place encryption supported)
 * @note in and out may overlap if out >= in + 64 (forward overlap only)
 * @note All data processed in big-endian format per Charybdis specification
 * @note Function is constant-time for the same nblocks value
 *
 * @return 0 on success, -1 on invalid input or context error.
 */
int charybdis_avx2_encrypt_blocks(const uint8_t* in,
                                   uint8_t* out,
                                   size_t nblocks,
                                   const charybdis_avx2_context_t* ctx);

/**
 * @brief Decrypt multiple 64-byte blocks using AVX2
 * 
 * 
 * @param[in]  in       Input ciphertext blocks (64 * nblocks bytes)
 * @param[out] out      Output plaintext blocks (64 * nblocks bytes)
 * @param[in]  nblocks  Number of 64-byte blocks to decrypt  
 * @param[in]  ctx      Initialized AVX2 context
 *
 * @return 0 on success, -1 on invalid input or context error.
 */
int charybdis_avx2_decrypt_blocks(const uint8_t* in,
                                   uint8_t* out,
                                   size_t nblocks,
                                   const charybdis_avx2_context_t* ctx);

#ifdef __cplusplus
}
#endif

#endif /* CHARYBDIS_AVX2_H */
