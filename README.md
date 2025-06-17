# Charybdis Block Cipher

[![License: CC0-1.0](https://img.shields.io/badge/License-CC0%201.0-lightgrey.svg)](http://creativecommons.org/publicdomain/zero/1.0/)

Charybdis is a high-security symmetric-key block cipher designed for applications like encrypted cold storage. It is a Substitution-Permutation Network (SPN) operating on 512-bit data blocks with a 256-bit key. The cipher is structured with 22 rounds to provide a conservative security margin.

This repository contains the reference C implementation, an AVX2-optimized version, and the official specification.

## Features

*   **Block Size:** 512 bits (64 bytes)
*   **Key Size:** 256 bits (32 bytes)
*   **Rounds:** 22
*   **Structure:** Substitution-Permutation Network (SPN)
*   **ARX-based Non-linear Layer:** For diffusion and side-channel resistance.
*   **Full-State Constant Injection:** For structural attack resistance.
*   **Sponge-based Key Schedule:** 1024-bit internal state for robust key derivation.
*   **Transparent Constants:** All constants derived from SHAKE256.
*   **AVX2 Optimization:** High-performance implementation for modern x86-64 CPUs.

## Algorithm Parameters

| Parameter        | Value                         | Description      |
| :--------------- | :---------------------------- | :--------------- |
| Block Size       | 512 bits                      | (64 bytes)       |
| Key Size         | 256 bits                      | (32 bytes)       |
| Internal State   | 512 bits                      | `4x4` matrix of 32-bit words |
| **Rounds**       | **22**                        |                  |
| **Subkeys**      | **24** (`K[0]`...`K[23]`)     | 512-bit each     |

For the complete algorithm details, see the [Charybdis Specification](./doc/Charybdis-v1-spec.md).

## Directory Structure

```
.
├── .gitignore                    # Git ignore file
├── LICENSE                       # CC0 1.0 Universal License file
├── README.md                     # This README file
├── doc/
│   └── Charybdis-v1-spec.md      # Official Charybdis specification
├── msvc/
│   ├── charybdis_bench.sln       # Visual Studio solution for Charybdis benchmarks
│   └── charybdis_bench.vcxproj   # Visual Studio project file for Charybdis benchmarks
├── src/
│   ├── charybdis.c               # Reference C implementation, tests, and benchmarks
│   ├── charybdis.h               # Header for reference implementation
│   ├── charybdis_avx2.c          # AVX2 optimized C implementation
│   └── charybdis_avx2.h          # Header for AVX2 implementation
└── tool/
    └── charybdis_constants.c     # Constants generation program for Charybdis specification
```

## Building

You can compile the reference implementation using a standard C compiler (e.g., GCC, Clang).

### Compiling with Tests

To compile the reference implementation with self-tests enabled:

```bash
gcc -o charybdis_test -DSELF_TEST src/charybdis.c src/charybdis_avx2.c -mavx2
```

### Compiling with Benchmarks

To compile the reference implementation with benchmarks enabled:

```bash
gcc -o charybdis_benchmark -DBENCHMARK src/charybdis.c src/charybdis_avx2.c -mavx2 -O2
```
*(Optimization (`-O2` or `-O3`) is recommended for benchmarks. `-mavx2` is needed for the AVX2 part of the benchmark.)*

### Compiling Constants Generator

To compile the constants generation utility:

```bash
gcc -o charybdis_constants tool/charybdis_constants.c -lssl -lcrypto
```

## Running

### Tests

After compiling with `SELF_TEST` defined, run the executable:

```bash
./charybdis_test
```
It will perform self-tests for both the reference and AVX2 (if available) implementations and print the results.

### Benchmarks

After compiling with `BENCHMARK` defined, run the executable:

```bash
./charybdis_benchmark
```
It will run performance benchmarks for both implementations across various data sizes.

### Constants Generation

After compiling the constants generator, run:

```bash
./charybdis_constants
```
It will generate and display all cipher constants for verification.

## Usage

### Reference Implementation

```c
#include "src/charybdis.h"
#include <stdio.h>
#include <string.h>

int main() {
    uint8_t key[CHARYBDIS_KEY_SIZE] = { /* your 256-bit key */ };
    uint8_t plaintext[CHARYBDIS_BLOCK_SIZE] = { /* your 512-bit block */ };
    uint8_t ciphertext[CHARYBDIS_BLOCK_SIZE];
    uint8_t decrypted_text[CHARYBDIS_BLOCK_SIZE];

    uint32_t subkeys[CHARYBDIS_SUBKEYS][4][4];

    // 1. Key Schedule
    Charybdis_KeySchedule(key, subkeys);

    // 2. Encrypt
    Charybdis_EncryptBlock(plaintext, ciphertext, subkeys);

    // 3. Decrypt
    Charybdis_DecryptBlock(ciphertext, decrypted_text, subkeys);

    // Verify
    if (memcmp(plaintext, decrypted_text, CHARYBDIS_BLOCK_SIZE) == 0) {
        printf("Reference Enc/Dec successful!\n");
    } else {
        printf("Reference Enc/Dec failed!\n");
    }

    return 0;
}
```

### AVX2 Optimized Implementation

```c
#include "src/charybdis.h"       // For Charybdis_KeySchedule and constants
#include "src/charybdis_avx2.h" // For AVX2 functions
#include <stdio.h>
#include <string.h>
#include <stdlib.h> // For _aligned_malloc/_aligned_free or aligned_alloc

int main() {
    if (!charybdis_avx2_available()) {
        printf("AVX2 not available on this system.\n");
        return 1;
    }

    uint8_t key[CHARYBDIS_KEY_SIZE] = { /* your 256-bit key */ };
    size_t num_blocks = 8; // AVX2 implementation processes 8 blocks in parallel optimally
    size_t data_size = num_blocks * CHARYBDIS_BLOCK_SIZE;

    // Allocate aligned memory for AVX2 operations
#ifdef _WIN32
    uint8_t* plaintext = (uint8_t*)_aligned_malloc(data_size, 32);
    uint8_t* ciphertext = (uint8_t*)_aligned_malloc(data_size, 32);
    uint8_t* decrypted_text = (uint8_t*)_aligned_malloc(data_size, 32);
#else
    uint8_t* plaintext = (uint8_t*)aligned_alloc(32, data_size);
    uint8_t* ciphertext = (uint8_t*)aligned_alloc(32, data_size);
    uint8_t* decrypted_text = (uint8_t*)aligned_alloc(32, data_size);
#endif

    if (!plaintext || !ciphertext || !decrypted_text) {
        printf("Memory allocation failed.\n");
        // free buffers
        return 1;
    }

    // Initialize plaintext (e.g., fill with some data)
    for(size_t i = 0; i < data_size; ++i) plaintext[i] = (uint8_t)i;

    uint32_t scalar_subkeys[CHARYBDIS_SUBKEYS][4][4];
    charybdis_avx2_context_t avx2_ctx;

    // 1. Generate scalar subkeys
    Charybdis_KeySchedule(key, scalar_subkeys);

    // 2. Initialize AVX2 context
    if (charybdis_avx2_init_context(&avx2_ctx, scalar_subkeys) != 0) {
        printf("Failed to initialize AVX2 context.\n");
        // free buffers
        return 1;
    }

    // 3. Encrypt blocks
    charybdis_avx2_encrypt_blocks(plaintext, ciphertext, num_blocks, &avx2_ctx);

    // 4. Decrypt blocks
    charybdis_avx2_decrypt_blocks(ciphertext, decrypted_text, num_blocks, &avx2_ctx);

    // Verify
    if (memcmp(plaintext, decrypted_text, data_size) == 0) {
        printf("AVX2 Enc/Dec successful!\n");
    } else {
        printf("AVX2 Enc/Dec failed!\n");
    }

    // 5. Clear context securely
    charybdis_avx2_clear_context(&avx2_ctx);

    // Free aligned memory
#ifdef _WIN32
    _aligned_free(plaintext);
    _aligned_free(ciphertext);
    _aligned_free(decrypted_text);
#else
    free(plaintext);
    free(ciphertext);
    free(decrypted_text);
#endif

    return 0;
}
```

## License

This work is dedicated to the public domain under the CC0 1.0 Universal license. See the [LICENSE](./LICENSE) file for details.

## Disclaimer

This is a reference implementation intended for educational and research purposes. It has not been optimized for performance beyond the provided AVX2 implementation or hardened against all possible side-channel attacks. Production use should employ additional protections and thorough review.
