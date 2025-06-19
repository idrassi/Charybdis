/**
 * Constant generation program for the Charybdis block cipher.
 * 
 * Author: Mounir IDRASSI <mounir.idrassi@amcrypto.jp>
 * Version: 1.0
 * Date: June 17, 2025
 * 
 * This program uses the OpenSSL library to derive all round constants (RC),
 * key schedule initialization constants (C_INIT), and key schedule permutation
 * round constants (RC_F) from their specified public seeds using SHAKE256.
 *
 * The purpose of this program is to provide a transparent and verifiable
 * reference for the origin and correctness of all constants used in the
 * Charybdis specification v1.0
 *
 * Compilation:
 *   gcc charybdis_constants.c -o charybdis_constants -lssl -lcrypto
 *
 * Usage:
 *   ./charybdis_constants
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/**
 * @brief Prints an array of 32-bit constants in little-endian format.
 *
 * @param title A descriptive title for the constant block.
 * @param name The name of the constant array to be printed.
 * @param constants A buffer containing the constants as raw bytes.
 * @param num_constants The total number of 32-bit constants in the buffer.
 * @param items_per_line The number of constants to print on each line.
 */
void print_constants(const char* title, const char* name, const uint8_t* constants, size_t num_constants, size_t items_per_line) {
    printf("// %s\n", title);
    printf("static const uint32_t %s[%zu] = {\n", name, num_constants);

    for (size_t i = 0; i < num_constants; ++i) {
        if (i % items_per_line == 0) {
            printf("    ");
        }

        // Convert 4 bytes to a uint32_t using LITTLE-ENDIAN interpretation.
        // The first byte from the SHAKE stream is the least significant byte (LSB).
        const uint8_t* p = &constants[i * 4];
        uint32_t val = (uint32_t)p[0] |
                       ((uint32_t)p[1] << 8) |
                       ((uint32_t)p[2] << 16) |
                       ((uint32_t)p[3] << 24);

        printf("0x%08X", val);

        if (i < num_constants - 1) {
            printf(",");
        }

        if ((i + 1) % items_per_line == 0 || i == num_constants - 1) {
            printf("\n");
        }
        else {
            printf(" ");
        }
    }
    printf("};\n\n");
}


/**
 * @brief Generates a stream of bytes using SHAKE256.
 *
 * @param seed The input seed string for the SHAKE256 function.
 * @param out_buffer The buffer to store the generated output.
 * @param out_len The desired number of bytes to generate.
 * @return 1 on success, 0 on failure.
 */
int generate_shake256(const char* seed, uint8_t* out_buffer, size_t out_len) {
    EVP_MD_CTX* mdctx = NULL;
    const EVP_MD* shake256 = NULL;
    int success = 0;

    shake256 = EVP_shake256();
    if (shake256 == NULL) {
        fprintf(stderr, "Error: SHAKE256 not available.\n");
        goto err;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "Error: EVP_MD_CTX_new failed.\n");
        goto err;
    }

    if (1 != EVP_DigestInit_ex(mdctx, shake256, NULL)) {
        fprintf(stderr, "Error: EVP_DigestInit_ex failed.\n");
        goto err;
    }

    if (1 != EVP_DigestUpdate(mdctx, seed, strlen(seed))) {
        fprintf(stderr, "Error: EVP_DigestUpdate failed.\n");
        goto err;
    }

    // EVP_DigestFinalXOF is used for eXtendable-Output Functions like SHAKE
    if (1 != EVP_DigestFinalXOF(mdctx, out_buffer, out_len)) {
        fprintf(stderr, "Error: EVP_DigestFinalXOF failed.\n");
        goto err;
    }

    success = 1;

err:
    EVP_MD_CTX_free(mdctx);
    return success;
}

int main() {
    printf("--- Charybdis v1.0 Little Endian Constant Generation Utility ---\n\n");

    // --- Generate Cipher Round Constants (RC) ---
    const char* rc_seed = "Charybdis-v1.0";
    #define RC_NUM_CONSTANTS 352 // 22 rounds * 16 words
    #define RC_BYTES (RC_NUM_CONSTANTS * 4)
    uint8_t rc_buffer[RC_BYTES];

    if (!generate_shake256(rc_seed, rc_buffer, RC_BYTES)) {
        return 1;
    }
    print_constants("Round Constants (RC) for 22 rounds", "RC", rc_buffer, RC_NUM_CONSTANTS, 8);


    // --- Generate Key Schedule Constants (C_INIT, RC_F, KSC) ---
    const char* ks_seed = "Charybdis-Constants-v1.0";
    #define C_INIT_NUM_CONSTANTS 24
    #define RC_F_NUM_CONSTANTS 64 // 16 rounds * 4 words
    #define KSC_NUM_CONSTANTS 736 // 23 subkeys * 32 words
    #define TOTAL_KS_NUM_CONSTANTS (C_INIT_NUM_CONSTANTS + RC_F_NUM_CONSTANTS + KSC_NUM_CONSTANTS)
    #define TOTAL_KS_BYTES (TOTAL_KS_NUM_CONSTANTS * 4)
    uint8_t ks_buffer[TOTAL_KS_BYTES];

    if (!generate_shake256(ks_seed, ks_buffer, TOTAL_KS_BYTES)) {
        return 1;
    }

    // Print the C_INIT part
    print_constants("Initialization constants (C_INIT) for the key schedule state (KSS)", "C_INIT",
        ks_buffer, C_INIT_NUM_CONSTANTS, 8);

    // Print the RC_F part by pointing to the correct offset in the buffer
    print_constants("Key schedule permutation round constants (RC_F) for 16 rounds", "RC_F",
        ks_buffer + (C_INIT_NUM_CONSTANTS * 4), RC_F_NUM_CONSTANTS, 8);

    // Print the KSC part by pointing to the correct offset in the buffer
    print_constants("Key Schedule domain separation Constants (KSC) ", "KSC",
        ks_buffer + (C_INIT_NUM_CONSTANTS + RC_F_NUM_CONSTANTS) * 4, KSC_NUM_CONSTANTS, 8);

    return 0;
}
