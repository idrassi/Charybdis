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
*   **AVX2 Optimization:** High-performance implementation for modern x86-64 CPUs (3.6 cpb, 630MiB/s on 2.4 GHz Core i9-13900HX).


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
├── CMakeLists.txt                # CMake build configuration file
├── LICENSE                       # CC0 1.0 Universal License file
├── README.md                     # This README file
├── doc/
│   └── Charybdis-v1-spec.md      # Official Charybdis specification
├── src/
│   ├── charybdis.c               # Reference C implementation, tests, and benchmarks
│   ├── charybdis.h               # Header for reference implementation
│   ├── charybdis_avx2.c          # AVX2 optimized C implementation
│   └── charybdis_avx2.h          # Header for AVX2 implementation
├── test_vectors/                 # Test vectors for Charybdis
└── tool/
    └── charybdis_constants.c     # Constants generation program for Charybdis specification
```

## Building

Charybdis uses CMake for cross-platform builds. The CMake build will generate three binaries by default:

- **charybdis_test**: Self-tests and benchmarks of the reference and AVX2 implementations.
- **charybdis_constants**: Utility to generate and display all cipher constants.
- **charybdis_test_vector_gen**: Utility to generate test vectors.

### Building with CMake

1. Create a build directory and run CMake:

   ```bash
   mkdir build
   cd build
   cmake ..
   cmake --build . --config Release
   ```

2. The resulting binaries will be located in the `build` directory.

#### Specifying OpenSSL Location (Windows)

If you are building on Windows and OpenSSL is not installed in a standard location, you can specify the root directory of your OpenSSL installation using the `OPENSSL_ROOT_DIR` variable. This is especially useful if your OpenSSL headers and libraries are under a custom path (e.g., `C:/dev/libraries/openssl`):

```bash
cmake .. -DOPENSSL_ROOT_DIR=C:/dev/libraries/openssl
```

If you are using **MSYS2 with MinGW64**, you can specify the OpenSSL root as follows:

```bash
cmake .. -DOPENSSL_ROOT_DIR=/mingw64
```

On MSYS2, install the OpenSSL headers and libraries with:

```bash
pacman -S mingw-w64-x86_64-openssl
```

Make sure that the `include` and `lib` folders are present under the specified OpenSSL root directory.

## Running

### Tests

After building, run the test executable:

```bash
./charybdis_test
```
It will perform self-tests for both the reference and AVX2 (if available) implementations and print the results.
It will also run performance benchmarks for both implementations across various data sizes.

### Constants Generation

After building, run the constants generator:

```bash
./charybdis_constants
```
It will generate and display all cipher constants for verification.

### Test Vector Generation

To generate test vectors, run:

```bash
./charybdis_test_vector_gen
```
This will create test vectors in the `test_vectors/` directory.

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
#define _XOPEN_SOURCE  500 // for posix_memalign
#include "src/charybdis.h"       // For Charybdis_KeySchedule and constants
#include "src/charybdis_avx2.h" // For AVX2 functions
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static inline void* malloc_aligned(size_t size, size_t alignment) {
#ifdef _WIN32
    return _aligned_malloc(size, alignment);
#else
    void* ptr = NULL;
    if (posix_memalign(&ptr, alignment, size) != 0) {
        return NULL;
    }
    return ptr;
#endif
}

#ifdef _WIN32
    #define free_aligned(x) _aligned_free(x)
#else
    #define free_aligned(x) free(x)
#endif

int main() {
    if (!charybdis_avx2_available()) {
        printf("AVX2 not available on this system.\n");
        return 1;
    }

    uint8_t key[CHARYBDIS_KEY_SIZE] = { /* your 256-bit key */ };
    size_t num_blocks = 8; // AVX2 implementation processes 8 blocks in parallel optimally
    size_t data_size = num_blocks * CHARYBDIS_BLOCK_SIZE;

    // Allocate aligned memory for AVX2 operations
    uint8_t* plaintext = (uint8_t*)malloc_aligned(data_size, 32);
    uint8_t* ciphertext = (uint8_t*)malloc_aligned(data_size, 32);
    uint8_t* decrypted_text = (uint8_t*)malloc_aligned(data_size, 32);

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
    free_aligned(plaintext);
    free_aligned(ciphertext);
    free_aligned(decrypted_text);

    return 0;
}
```

## License

This work is dedicated to the public domain under the CC0 1.0 Universal license. See the [LICENSE](./LICENSE) file for details.

## Disclaimer

This is a reference implementation intended for educational and research purposes. It has not been optimized for performance beyond the provided AVX2 implementation or hardened against all possible side-channel attacks. Production use should employ additional protections and thorough review.
