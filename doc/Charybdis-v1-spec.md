### **Charybdis Block Cipher**

**Author:** Mounir IDRASSI <mounir.idrassi@amcrypto.jp><br>
**Date:** June 17, 2025<br>
**Version:** 1.0<br>
**License:** CC0 1.0 Universal (Public Domain Dedication)<br>

#### **Abstract**

Charybdis is a symmetric-key block cipher designed for applications requiring high security margins, such as encrypted cold storage. It is a Substitution-Permutation Network (SPN) operating on 512-bit data blocks with a 256-bit key. The cipher uses 22 rounds, chosen to provide a conservative security margin.

The design follows established cryptographic principles. The round function uses the classical SPN model with the goal of making security properties independent of the key material. It employs an Addition, Rotation, and XOR (ARX) construction for its non-linear layer, designed to provide strong diffusion while potentially offering resistance to cache and timing-based side-channel attacks. A full-state constant injection in every round aims to provide defense against structural attacks. The key schedule uses a 1024-bit sponge construction, designed to achieve a 256-bit security level and to resist related-key attacks. All constants are transparently derived from a public seed using SHAKE256.

---

### **1. Introduction and Parameters**

#### **1.1. High-Level Parameters**

| Parameter | Value | Description |
| :--- | :--- | :--- |
| Block Size | 512 bits | (64 bytes) |
| Key Size | 256 bits | (32 bytes) |
| Internal State | 512 bits | `4×4` matrix of 32-bit words |
| **Rounds** | **22** | |
| **Subkeys** | **24** (`K[0]`...`K[23]`) | 512-bit each |

#### **1.2. Data Types and Notation**

*   **Data Types:** The fundamental unit of operation is the 32-bit unsigned integer, referred to as a "word".
*   **State Matrix:** The 512-bit internal state `S` is represented as a `4×4` matrix of words. The matrix is populated from an input block in row-major order.
*   **Byte Order:** All multi-byte values are processed using a **little-endian** convention. A 4-byte sequence from a byte stream `B0, B1, B2, B3` is converted to a 32-bit word `W` as:
    `W = (B3 << 24) | (B2 << 16) | (B1 << 8) | B0`
*   **Operators:** `⊕` (Bitwise XOR), `+` (Addition modulo 2³²), `≪ n` (Bitwise left rotation by n positions), `≫ n` (Bitwise right rotation by n positions).

---

### **2. Cipher Algorithm**

#### **2.1. Encryption**

To encrypt a 512-bit plaintext block `P` using a 256-bit master key `M`:

1.  **Key Schedule:** Generate subkeys `K[0]`...`K[23]` from `M` (see Section 5).
2.  **Initial Whitening:** The state `S` is initialized by XORing `P` with `K[0]`.
    `S ← P ⊕ K[0]`
3.  **Main Rounds:** For `r` from 1 to 22, apply the round function:
    `S ← Round(S, K[r], r)`
4.  **Final Whitening:** The final state `S` is XORed with `K[23]`.
    `S ← S ⊕ K[23]`
5.  **Output:** The ciphertext `C` is the final state `S`.
    `C = S`

#### **2.2. Decryption**

Decryption reverses the encryption process exactly.

1.  **Key Schedule:** Generate subkeys `K[0]`...`K[23]` from `M`.
2.  **Initial State:** Initialize the state `S` with the ciphertext `C` XORed with the last subkey.
    `S ← C ⊕ K[23]`
3.  **Inverse Main Rounds:** For `r` from 22 down to 1, apply the inverse round function:
    `S ← InverseRound(S, K[r], r)`
4.  **Final Whitening:** The plaintext `P` is recovered by XORing the state `S` with `K[0]`.
    `P ← S ⊕ K[0]`

---

### **3. The Round Function**

The round function follows a classical SPN structure to facilitate security analysis.

#### **3.1. `Round(S, K_r, r)`**

1.  **SubConstants(S, r):** XORs round-dependent constants into the full state.
2.  **ColumnMix(S):** Applies a non-linear mixing operation to each column.
3.  **ShiftRows(S):** Permutes data between columns.
4.  **AddRoundKey(S, K_r):** XORs the round subkey with the state.

#### **3.2. `InverseRound(S, K_r, r)`**

The inverse operations are applied in reverse order:

1.  **AddRoundKey(S, K_r):** (Self-inverse operation)
2.  **InverseShiftRows(S):**
3.  **InverseColumnMix(S):**
4.  **SubConstants(S, r):** (Self-inverse operation)

---

### **4. Round Function Components**

#### **4.1. SubConstants**
This operation XORs a unique 32-bit constant into each of the 16 words of the state in every round.

*   **Constant Generation:** The 352 (22 rounds × 16 words) 32-bit constants (`RC`) are generated using SHAKE256.
    1.  **Input Seed:** The input to SHAKE256 is the 14-byte ASCII sequence `"Charybdis-v1.0"` (without null terminator):
        ```
            0x43 0x68 0x61 0x72 0x79 0x62 0x64 0x69 0x73 0x2D 0x76 0x31
            0x2E 0x30
        ```
    2.  **SHAKE256 Invocation:** SHAKE256 is applied to produce a 1408-byte output stream.
    3.  **Output Parsing:** The 1408-byte stream is parsed into 352 consecutive 32-bit words. Each 4-byte chunk is interpreted using **little-endian** byte order as defined in Section 1.2.

*   **Operation:** For round `r` (1 to 22), and for `i,j` from 0 to 3:
    `S[i][j] ← S[i][j] ⊕ RC[(r-1)×16 + (4×i+j)]`
*   **Inverse:** The operation is self-inverse.

(See Appendix A.1 for pre-computed `RC` values)

#### **4.2. ColumnMix**
This ARX-based layer aims to provide non-linearity and intra-column diffusion. It is applied independently to each of the four state columns. The transformation uses core functions `G` and `H`, which are interleaved and applied twice each per column with a permutation.

```c
// Rotation constants for G_Mix and H_Mix.
#define R1 13
#define R2 19
#define R3 23
#define R4 29

#define RH1 9
#define RH2 17
#define RH3 21
#define RH4 27

// G_Mix: The core function G(a, b, c, d).
void G_Mix(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *a += *b; *d ^= *a; *d = (*d >> R1) | (*d << (32-R1));
    *c += *d; *b ^= *c; *b = (*b >> R2) | (*b << (32-R2));
    *a += *b; *d ^= *a; *d = (*d >> R3) | (*d << (32-R3));
    *c += *d; *b ^= *c; *b = (*b >> R4) | (*b << (32-R4));
}

// Inverse G_Mix: The core inverse function G_inv(a, b, c, d).
void InverseG_Mix(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *b = ((*b << R4) | (*b >> (32-R4))) ^ *c; *c -= *d;
    *d = ((*d << R3) | (*d >> (32-R3))) ^ *a; *a -= *b;
    *b = ((*b << R2) | (*b >> (32-R2))) ^ *c; *c -= *d;
    *d = ((*d << R1) | (*d >> (32-R1))) ^ *a; *a -= *b;
}

// H_Mix: The core function H(a, b, c, d).
void H_Mix(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *a += *b; *d ^= *a; *d = (*d >> RH1) | (*d << (32-RH1));
    *c += *d; *b ^= *c; *b = (*b >> RH2) | (*b << (32-RH2));
    *a += *b; *d ^= *a; *d = (*d >> RH3) | (*d << (32-RH3));
    *c += *d; *b ^= *c; *b = (*b >> RH4) | (*b << (32-RH4));
}

// Inverse H_Mix: The core inverse function H_inv(a, b, c, d).
void InverseH_Mix(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *b = ((*b << RH4) | (*b >> (32-RH4))) ^ *c; *c -= *d;
    *d = ((*d << RH3) | (*d >> (32-RH3))) ^ *a; *a -= *b;
    *b = ((*b << RH2) | (*b >> (32-RH2))) ^ *c; *c -= *d;
    *d = ((*d << RH1) | (*d >> (32-RH1))) ^ *a; *a -= *b;
}

// The full ColumnMix operation applied to the entire state.
void ColumnMix(uint32_t S[4][4]) {
    for (int j = 0; j < 4; j++) {
        uint32_t col[4] = {S[0][j], S[1][j], S[2][j], S[3][j]};
        G_Mix(&col[0], &col[1], &col[2], &col[3]);
        H_Mix(&col[0], &col[1], &col[2], &col[3]);
        H_Mix(&col[2], &col[3], &col[0], &col[1]);
        G_Mix(&col[2], &col[3], &col[0], &col[1]);
        S[0][j] = col[0]; S[1][j] = col[1]; S[2][j] = col[2]; S[3][j] = col[3];
    }
}

// The full InverseColumnMix operation applied to the entire state.
void InverseColumnMix(uint32_t S[4][4]) {
    for (int j = 0; j < 4; j++) {
        uint32_t col[4] = {S[0][j], S[1][j], S[2][j], S[3][j]};
        InverseG_Mix(&col[2], &col[3], &col[0], &col[1]);
        InverseH_Mix(&col[2], &col[3], &col[0], &col[1]);
        InverseH_Mix(&col[0], &col[1], &col[2], &col[3]);
        InverseG_Mix(&col[0], &col[1], &col[2], &col[3]);
        S[0][j] = col[0]; S[1][j] = col[1]; S[2][j] = col[2]; S[3][j] = col[3];
    }
}
```

#### **4.3. ShiftRows**
This layer aims to provide inter-column diffusion by cyclically shifting the words within each row to the left by `[0, 1, 2, 3]` positions, respectively. The inverse shifts rows to the right by the same offsets.

##### **4.3.1. Formal Definition**
Let `S` be the state before the operation and `S'` be the state after. The operation is defined by the shift offsets vector `SHIFTS = [0, 1, 2, 3]`.

**ShiftRows:** For each row `i` from 0 to 3, the words are shifted left by `SHIFTS[i]` positions.
`S'[i][j] = S[i][(j + SHIFTS[i]) mod 4]`
for `0 ≤ i, j < 4`.

**InverseShiftRows:** For each row `i` from 0 to 3, the words are shifted right by `SHIFTS[i]` positions.
`S'[i][j] = S[i][(j - SHIFTS[i] + 4) mod 4]`
for `0 ≤ i, j < 4`.

##### **4.3.2. Equivalent Pseudocode**
```c
static const int SHIFTS[4] = {0, 1, 2, 3};

// ShiftRows: Shift row i left by SHIFTS[i] positions.
void ShiftRows(uint32_t S[4][4]) {
    for (int i = 0; i < 4; i++) {
        uint32_t temp[4];
        // Copy row to temporary array
        for (int j = 0; j < 4; j++) {
            temp[j] = S[i][j];
        }
        // Shift left by SHIFTS[i] positions
        for (int j = 0; j < 4; j++) {
            S[i][j] = temp[(j + SHIFTS[i]) % 4];
        }
    }
}

// InverseShiftRows: Shift row i right by SHIFTS[i] positions.
void InverseShiftRows(uint32_t S[4][4]) {
    for (int i = 0; i < 4; i++) {
        uint32_t temp[4];
        // Copy row to temporary array
        for (int j = 0; j < 4; j++) {
            temp[j] = S[i][j];
        }
        // Shift right by SHIFTS[i] positions
        for (int j = 0; j < 4; j++) {
            S[i][j] = temp[(j - SHIFTS[i] + 4) % 4];
        }
    }
}
```

#### **4.4. AddRoundKey**
This is a bitwise XOR of the state `S` with the round subkey `K_r`. For each element of the state matrix, where `0 ≤ i, j < 4`:
`S[i][j] ← S[i][j] ⊕ K_r[i][j]`
The operation is self-inverse.

---

### **5. The Key Schedule**

The key schedule expands the 256-bit master key into 24 subkeys using a sponge construction. This design aims to make each subkey a complex, non-linear function of the entire master key. It uses a dedicated 16-round permutation, `F_perm`, on a 1024-bit internal state.

#### **5.1. Key Schedule Parameters and Constants**

*   **Internal State (`KSS`):** 1024-bit (`4×8` matrix of words).
*   **Rate:** 512-bit (leftmost `4×4` part of `KSS`).
*   **Capacity:** 512-bit (rightmost `4×4` part of `KSS`).
*   **Permutation `F_perm`:** A dedicated **16-round** permutation on the 1024-bit state.
*   **Constants:** The initialization constants (`C_INIT`), the key schedule permutation's round constants (`RC_F`), and the key schedule domain separation constants (`KSC`) are generated using SHAKE256.

##### **Constant Generation Procedure**

1.  **Input Seed:** The input to SHAKE256 is the 24-byte ASCII sequence `"Charybdis-Constants-v1.0"` (without null terminator):
    ```
        0x43 0x68 0x61 0x72 0x79 0x62 0x64 0x69 0x73 0x2D 0x43 0x6F
        0x6E 0x73 0x74 0x61 0x6E 0x74 0x73 0x2D 0x76 0x31 0x2E 0x30
    ```
2.  **SHAKE256 Invocation:** SHAKE256 is applied to produce a **3296-byte** output stream.
3.  **Output Parsing:** The 3296-byte stream is processed sequentially. Each 4-byte chunk is interpreted using **little-endian** byte order as defined in Section 1.2.
    *   **`C_INIT` Generation:** The first 96 bytes (24 words) populate `C_INIT[0]` to `C_INIT[23]`.
    *   **`RC_F` Generation:** The subsequent 256 bytes (64 words) populate `RC_F[0]` to `RC_F[63]`.
    *   **`KSC` Generation:** The final 2944 bytes (736 words) populate the Key Schedule domain separation Constants (`KSC`). These are organized as 23 constants of 1024 bits (32 words) each. `KSC[0]` consists of the first 32 words, `KSC[1]` the next 32, and so on.

Compliant implementations **MUST** use the pre-computed values listed in Appendix A.2, A.3, and A.4, which can be verified using the procedure above.

#### **5.2. The Key Schedule Permutation `F_perm`**

`F_perm` is a 16-round permutation using a decoupled ARX primitive, `F_G_Mix`.

```c
#define F_R1 11
#define F_R2 19
#define F_R3 23
#define F_R4 29

// F_G_Mix is identical in operation to G_Mix but uses F_R1..F_R4.
void F_G_Mix(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *a += *b; *d ^= *a; *d = (*d >> F_R1) | (*d << (32-F_R1));
    *c += *d; *b ^= *c; *b = (*b >> F_R2) | (*b << (32-F_R2));
    *a += *b; *d ^= *a; *d = (*d >> F_R3) | (*d << (32-F_R3));
    *c += *d; *b ^= *c; *b = (*b >> F_R4) | (*b << (32-F_R4));
}

void F_perm_Round(uint32_t KSS[4][8], int r) {
    // 1. AddConstants: Add round constants into the main diagonal.
    for (int i = 0; i < 4; i++) { KSS[i][i] += RC_F[r * 4 + i]; }
    // 2. ColumnStep: Mix all 8 columns vertically.
    for (int j = 0; j < 8; j++) { F_G_Mix(&KSS[0][j], &KSS[1][j], &KSS[2][j], &KSS[3][j]); }
    // 3. DiagonalStep: Mix along diagonals.
    for (int i = 0; i < 4; i++) {
        F_G_Mix(&KSS[i][(0+i)%8], &KSS[i][(1+i)%8], &KSS[i][(2+i)%8], &KSS[i][(3+i)%8]);
        F_G_Mix(&KSS[i][(4+i)%8], &KSS[i][(5+i)%8], &KSS[i][(6+i)%8], &KSS[i][(7+i)%8]);
    }
}

void F_perm(uint32_t KSS[4][8]) {
    for (int r = 0; r < 16; r++) { F_perm_Round(KSS, r); }
}
```

#### **5.3. Key Generation Procedure**
1.  **Initialization:** The 1024-bit `KSS` is loaded with `M` (256 bits) in the first 8 words and `C_INIT` (768 bits) in the remaining 24 words. The master key `M` is placed in `KSS[0][0]` through `KSS[0][7]` using little-endian word parsing. The constants `C_INIT[0]` through `C_INIT[23]` are placed in `KSS[1][0]` through `KSS[3][7]`.
2.  **Absorption:** `F_perm(KSS)` is called once.
3.  **Squeezing:** For `i` from 0 to 23:
    a.  **Squeeze:** Subkey `K[i]` is extracted from the rate part of `KSS` (the leftmost 4×4 portion: `KSS[0][0]` through `KSS[3][3]`).
    b. **Domain Separation (if i < 23):** To provide strong, non-linear domain separation between subkey generations, a three-step process is applied:
        
        i.  **Inject Counter:** A round-dependent counter `(i + 1)` is added to four different words in the state to break symmetry.
            *   `KSS[0][7] += (i + 1)`
            *   `KSS[1][3] += (i + 1)`
            *   `KSS[2][6] += (i + 1)`
            *   `KSS[3][1] += (i + 1)`

        ii. **Inject Constant:** A unique 1024-bit constant, `KSC[i]`, is XORed with the entire `KSS` state. This prevents an attacker from using the linearity of the counter injection to create exploitable state conditions.
            ```c
            // For j from 0..3, k from 0..7
            // KSS[j][k] ^= KSC[i * 32 + j * 8 + k]
            ```
            
        iii. **Permute:** The internal permutation is applied to the modified state.
            *   `F_perm(KSS)`

---

### **6. Design Rationale**

Charybdis is based on conservative and well-studied cryptographic principles:

*   **Classical SPN Structure:** The round function `SubConstants → ColumnMix → ShiftRows → AddRoundKey` follows a well-analyzed structure. This design aims to make the properties of the non-linear layer independent of key material, potentially simplifying security analysis and defending against key-dependent attacks.

*   **Symmetry Breaking:** The `SubConstants` layer applies unique constants to the entire 512-bit state in every round. This approach, used in modern cipher designs, aims to defend against structural attacks such as slide, rotational, and invariant subspace cryptanalysis by ensuring no two rounds have identical transformations.

*   **Diffusion Strategy:** The combination of `ColumnMix` (designed for strong intra-column ARX diffusion) and `ShiftRows` (optimal inter-column permutation) aims to provide rapid and full diffusion. The 22-round count is chosen to provide a security margin against differential and linear cryptanalysis.

*   **Key Schedule Design:**
    *   **Permutation Security:** The internal permutation `F_perm` uses 16 rounds, chosen to provide a security margin against potential distinguishing attacks on the permutation itself. This design aims to help the 512-bit capacity of the sponge construction achieve a 256-bit security level.
    *   **Component Separation:** The use of a distinct permutation (`F_perm`) with different rotation constants for the key schedule is a deliberate design choice. It aims to cryptographically separate the key schedule from the main cipher, potentially preventing attacks that leverage properties from one component against the other.
    *   **Hardened Domain Separation:** Between each subkey extraction, the key schedule state is updated not only by applying the `F_perm` permutation but also through a robust domain separation mechanism. A simple counter is added to four state words to ensure uniqueness, and this is immediately followed by XORing a unique 1024-bit constant (`KSC`) into the full state. This two-part injection was adopted to close a theoretical gap identified in designs that use only linear (additive) counters. The full-state XOR ensures that any linear relationships an attacker might try to induce via the counter are immediately destroyed by a large, non-linear transformation before the next permutation, thus strengthening the independence of each subkey.

---

### **7. Test Vectors**

A compliant implementation **MUST** produce the following values from the given inputs. All values are hex-encoded strings representing byte arrays.

**Key (`M`):**
`000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F`

**Plaintext (`P`):**
`00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF`

**(Reference) Subkey `K[1]`:**
`F62149033F2EDE7A39AAE20F7FEB62E16421CEA2FA26732EE80BB31E62C793A3D4EF98AD47A9BA61300D36F51E2ECDCBC306468272C0B5A21B993316E8EC83D0`

**(Reference) State `S` after Round 1:**
`5FE67EA13D13DA6286832BB9EC9B4B517E4ADE4B2A38860C6C42888D6E3D50A7080335FD04398926C2828A0E92F42C1C7F2CC056947FF056A40DF879423001CF`

**Ciphertext (`C`):**
`4F27B8BFB0500FA67ACCCD946436DE03BE94C7BE56E0DD67B0EB66605FDD46ED8121F895A0AF582E185B45B930C37819AF483DB2B2A2406DCBC27DA5CBBABBF2`

---

### **8. Implementation Notes**
- All multi-byte values (plaintext, ciphertext, keys, subkeys) are processed in **little-endian** byte order when converting between byte arrays and 32-bit words.
- The state matrix `S[4][4]` is populated from a 64-byte input block in row-major order: bytes 0-3 become `S[0][0]`, bytes 4-7 become `S[0][1]`, etc., with each 4-byte group being interpreted as a little-endian word. On common little-endian CPUs, this allows for direct memory loads/stores (e.g., via `memcpy` or pointer casting) without byte swapping.

---

### **Appendix A: Pre-computed Constants**

#### **A.1. Round Constants (`RC`)**
```c
// Round Constants (RC) for 22 rounds
static const uint32_t RC[352] = {
    0x49E4AB09, 0x5162DB3D, 0x65C180C3, 0x6B337C7C, 0x0947E8C2, 0x0C542228, 0xBD2C29B1, 0x580DC135,
    0x99204A36, 0x17C5D802, 0xA400842E, 0xE9C4E23C, 0xC12ED428, 0xA2DAB568, 0x9EBE07BB, 0x72898513,
    0xF76D00FD, 0x9C6F794B, 0x7D5AD44F, 0x47B56292, 0xE6025A3D, 0xEDF80720, 0x20C657F1, 0x4395162B,
    0x06E46590, 0xBC516693, 0x2C093E26, 0xB1678516, 0xE72C28E9, 0xDD05E86A, 0xAED31295, 0x40C3D677,
    0x837FD877, 0xB61950BA, 0x674C07A4, 0x6B4279F7, 0xE69CB72B, 0xBE4709DC, 0xB4285315, 0xD7C713E9,
    0x4AEB3B54, 0x0EE611D8, 0x89DD7EEB, 0x042F4463, 0x7FCA132F, 0xC12B9096, 0x64CE30E1, 0xC715F52C,
    0x5149AA03, 0x510C5880, 0x7BD9B34A, 0xC00D59E7, 0x736BBBFF, 0x06670F0F, 0x032E7564, 0xB2BC5FFA,
    0x620F197C, 0xF3088945, 0xE362E3E9, 0x4864DE7B, 0x33A5665A, 0xF34DB2DF, 0x21382BCC, 0xB49BA35F,
    0x7D27734F, 0xA6DB1156, 0xF2EC4AF1, 0x690FD2F6, 0xF54AA809, 0x247A122A, 0x85274381, 0xD13A347F,
    0xACEB5617, 0x590AE3E9, 0x57CCFAE3, 0xD1060AF1, 0xC40E0EAF, 0x545A4DCA, 0xB8AC6F3F, 0xB0985466,
    0xDD565121, 0xE11BED19, 0xF14771AE, 0xD7AD1ABE, 0xD8B48FA2, 0x1D54ACB3, 0x3C3387A9, 0x3655D387,
    0x948C68CB, 0x9F94F38C, 0xF0B4FBC0, 0x1EB9D2C0, 0x232298C8, 0x6595423C, 0x140656A7, 0x0D032A20,
    0x3AF63AF5, 0xDB8D3AE4, 0x5E572E5E, 0xC8DF57DD, 0xD62E118C, 0x6673EA4C, 0x82DD067B, 0x7EB6A051,
    0x1925AA25, 0x13991B1A, 0x286DA015, 0x9E610395, 0xB21B048F, 0xDF01BB8E, 0x91A910D2, 0x3904593A,
    0x923DF194, 0x2AA4C3D3, 0x2AD9B207, 0x514F0D45, 0x34B1E6CB, 0x67717390, 0xEBA75EC9, 0x0694AC61,
    0xD5C1975D, 0x29BB0175, 0x33A24D43, 0x7AA56690, 0xB42F19B9, 0x72A9F181, 0x7AD6396D, 0xEBAC8CCC,
    0xA2441762, 0xFBB4AADB, 0x51382FBE, 0x8FCA8864, 0x9B2CF90F, 0x68E55D51, 0x65921959, 0x09B5FAD3,
    0xFAB6E9A8, 0x515B2AD5, 0x30D9723F, 0x55AEB76A, 0xDA1341F0, 0xE151E097, 0xC7E788CE, 0x28F2A0F4,
    0x413A9C4D, 0xCEC61977, 0x62FD8051, 0xEDE2BB9F, 0x5DB34734, 0xE87077DB, 0x46A10D36, 0x9B94F213,
    0x9AD57DDC, 0x3913D8E0, 0xE7842DE3, 0x0A62E385, 0xC5DAA02D, 0xC55BC5CF, 0xD7B0077C, 0xC57C652B,
    0x33B6B02E, 0x8BBFA1C6, 0xCD042F60, 0xBCD08D1D, 0x5FF64385, 0x66901B81, 0x909786BD, 0x3C2D5400,
    0xF07C8B77, 0x663E39B2, 0xC8AC04CF, 0xBC7727D6, 0x5EFC65DE, 0x34177ED5, 0x520E6C98, 0x4CBEDC3E,
    0xA7DB8FD4, 0x85ABC9E9, 0x860D16E2, 0x2ECD8B84, 0xCE7311F6, 0x20CA2785, 0xD3BDF31A, 0xF461F125,
    0x5597BD30, 0x77E10FF1, 0x76290EBB, 0x75A9D3BA, 0xAFD33300, 0xBD500787, 0x7CD4A812, 0x565382A5,
    0x2C9E95F5, 0x1BB55181, 0x73DE6268, 0x3C2C31BB, 0xBF55539E, 0x184DED72, 0x8DC14C7E, 0xE52B9F71,
    0x1C3DF327, 0xCE86A422, 0x09943884, 0x78891648, 0xC59D07FD, 0x404C8175, 0x1F949F8E, 0xF0A9DE13,
    0xE27D7CAB, 0x732A4516, 0x9C3CE306, 0x1F6D3F1C, 0xBFBDFA4E, 0x690B75F2, 0x07A4E8CC, 0x926CAD0E,
    0xB8A565F7, 0x31AAD54E, 0x91C6EAD8, 0x4C98E2DF, 0xFBD14903, 0x84DC674D, 0xFAE19853, 0xEEEE29DE,
    0xB466F338, 0x8B2CCA68, 0xD2BEB3C1, 0xBDFC1B04, 0x04623E3E, 0x632C6C69, 0xCEC61FB4, 0x149522EE,
    0x178B9848, 0xC3E995B9, 0x9A8D8A65, 0x78A35E05, 0xCBE104B9, 0xB3EE5FCD, 0x481EB903, 0x21CF75FD,
    0xADE8A65B, 0x9FF9F97D, 0xAF146F30, 0x0CEBF587, 0xA2D26B39, 0x239C59F7, 0xC57085BE, 0xDD4AB6C9,
    0x1D8B92C3, 0x286D4304, 0x0C91F7F8, 0xD246786A, 0xF007C35F, 0xC05D4640, 0x74564490, 0xAC7028E4,
    0x2BB817BB, 0xEC813385, 0x189F9BDC, 0x76649CA9, 0x6E619411, 0x068B3CCA, 0x22F3C66D, 0x8CF1A317,
    0x981EFC2B, 0xBFA32D9C, 0xB414CC4A, 0xE4FD0DDF, 0xF2A85859, 0xFC73A02C, 0x9FB19147, 0xC2CE9410,
    0x576A47DC, 0x1DB9F29C, 0x1CA49FCE, 0x5FDC4D4C, 0xB9F85726, 0x92AA70BD, 0x79BDAA65, 0x1D9C262D,
    0x651B144C, 0x3D53A967, 0x539091F8, 0xAFA3AA05, 0x3A4A846D, 0x832F42E3, 0x6B249C56, 0xD5D2BC93,
    0xC4C803F8, 0x167C8A49, 0x9DBE90F9, 0x2267E183, 0xAC79E064, 0x07163F07, 0x3A3F7370, 0xD09A578F,
    0x47D75DD9, 0x45B52F1E, 0x0454A224, 0xA99B26E0, 0xB24C0ACD, 0x42A1A1B3, 0x48DEC938, 0xDE294680,
    0x4E73FB0F, 0xC7F5E823, 0xC3FF5E97, 0x57CA69CC, 0xF4BC726F, 0xA414FACD, 0xF26D5DBA, 0xE4445DB7,
    0x02306C0B, 0x5F5A2FF2, 0x9EB766EF, 0x1B6B4556, 0x59379BDA, 0xFD2D0967, 0xD9A8216D, 0x78A202C0,
    0x7AF7DB27, 0x25B69D6F, 0xAF22C630, 0x4EB6EF72, 0x7CD28377, 0x8AA1DE7A, 0x4A4232E0, 0xD50F0E91,
    0xF812218E, 0x2C8E27E4, 0xEA1C4063, 0xDC3E0E71, 0xF8A7833C, 0x9AFBD5A4, 0x98D74BAD, 0x2EC7B1D5,
    0xA0639FA4, 0x000B024C, 0xC62B50A0, 0xF79056ED, 0x1B3DE3DE, 0xBFA29EE9, 0xBFAC297E, 0x74D9FE5C,
    0x1D60E54D, 0x279B4268, 0x51B9D6BB, 0xC88D1F37, 0x28EC8BDE, 0x36E56538, 0x5DA0D743, 0x081F73BC
};
```

#### **A.2. Key Schedule Initialization Constants (`C_INIT`)**
```c
// Initialization constants (C_INIT) for the key schedule state (KSS)
static const uint32_t C_INIT[24] = {
    0x613A9ABD, 0xD2434FD8, 0xDEDF9481, 0x2940B05C, 0xA9C7A722, 0xED6D094F, 0xC04A5F78, 0xBED3D4EA,
    0xEB2C1324, 0x08A4263C, 0xB4BA8A0E, 0xE0F2EAC4, 0x458CF930, 0x9CC9AA68, 0x0C630F1B, 0x61E5C7E3,
    0x5C5ED019, 0xD5E442C0, 0x1BEB9747, 0xA60CF0DE, 0x0267DB62, 0xA5C3A9C6, 0xEFD1CC0A, 0xCABCC8D1
};
```

#### **A.3. Key Schedule Permutation Round Constants (`RC_F`)**
```c
// Key schedule permutation round constants (RC_F) for 16 rounds
static const uint32_t RC_F[64] = {
    0x87EF983E, 0x4C33CE4B, 0xD4DE68D1, 0x48E5E385, 0x798239CA, 0xAA4279BD, 0x390419A6, 0x5CBBEF47,
    0x745F358C, 0xA61802E8, 0xC02B7871, 0xDE95BE90, 0xE160DE99, 0x34B2B34C, 0xB76707D0, 0x5096856F,
    0x1D22F712, 0xD899B75A, 0x6E02A988, 0x26FD16DC, 0xC2C52DEA, 0x637CFB4F, 0x6F1EDF4D, 0xCBF317CF,
    0x63E6123F, 0x113BE322, 0x97D01B1E, 0xF9B2DE10, 0x3BFBE353, 0x00AE19AC, 0x379822D4, 0x4F8D80FC,
    0x98C733EE, 0xBB41CAC3, 0x83A0EF8E, 0x101184E3, 0xFB293A75, 0x8682D077, 0x4B6BD920, 0x0F521E1D,
    0xD9B4C1D0, 0x02AB52FB, 0x01A82B82, 0xE05D60AB, 0x718362E4, 0x62DC03A7, 0x20F6EE26, 0xF7805654,
    0x282DAF79, 0x6A9BA185, 0xCC74D6C7, 0xA959E475, 0x330ADCC0, 0x2B27748D, 0xA5048432, 0x91D64C6E,
    0xEDEBE8CE, 0x8B4E252F, 0x5A66271A, 0x8499A351, 0x63AA49B0, 0x7B8729B5, 0xE926B00D, 0xC42BC689
};
```

#### **A.4. Key Schedule Domain Separation Constants (`KSC`)**
```c
// Key Schedule domain separation Constants (KSC) for 23 rounds of squeezing.
// Each round uses a 1024-bit (32 x uint32_t) constant. 
// Total size: 23 * 32 = 736 words.
static const uint32_t KSC[736] = {
    0x5614CE22, 0x07CC5F85, 0x6EC4FA38, 0xE764DB84, 0xD4626EB5, 0x459D17FB, 0x20D177A8, 0x11A1DB20,
    0x96EAB452, 0xF7422063, 0xF1087E71, 0xE49BDFEF, 0x2D9D3608, 0x55F29039, 0xD4991F7E, 0x9864369F,
    0x9FE3C339, 0x7D0A4299, 0x823582DC, 0xC5770C14, 0xD946061D, 0xDA066059, 0xA5C753D5, 0xCCBE0152,
    0x909BEE86, 0xEA33B516, 0x097CF62E, 0x4D17E7F0, 0x508A2010, 0x263E2062, 0xEA65A8B2, 0x3102D862,
    0x61CE0678, 0x1AEC974A, 0x42840287, 0x33674A1B, 0xB70F54F2, 0x41E99C0F, 0x60F780CE, 0x677F5CB6,
    0xD9431C7A, 0xE6CF1B07, 0xE67F3B10, 0x5FFC8732, 0x414F2AF5, 0xA5C4980D, 0x0971379B, 0xD0E36DA1,
    0xC2D8C2D3, 0x65BBAC18, 0x8CCC1749, 0x0F0FE003, 0x61CDC953, 0x20F3D7A3, 0xE472E647, 0x9A4B0890,
    0xA4270EBB, 0xA1AE6D52, 0x1C053ABB, 0xFE42A158, 0xD0841FD3, 0x28A2E6FB, 0x723B41F1, 0x21AB75E3,
    0x5A7FBF1E, 0x4B678D96, 0x241F9CAD, 0x73B2E565, 0xB0362B6B, 0xF8320AAC, 0xCB6764C0, 0xFAE75958,
    0x2F422848, 0x76F38142, 0x3770E09D, 0x65E06F11, 0xE2318D20, 0xFABAA37D, 0x4479FED1, 0xC217682D,
    0xE23E85E1, 0x3752E44C, 0x3AD1374B, 0x6D6A351B, 0xA6B2DDF8, 0x9A566308, 0xD23D4EF4, 0x8E77C6A7,
    0xC88C0DCD, 0x1B7FEA33, 0x4525AD2C, 0x5B793B3F, 0x6CDBB3BA, 0x9B931CCE, 0xB1AB7BDF, 0x314F4F7A,
    0xAA88CD0A, 0xCF6F9F8C, 0xF6E12F82, 0xDF9E0EED, 0xCDF9396B, 0x1543F1A8, 0xF561CE7F, 0xF65A12E6,
    0x40460C4A, 0x3B23B847, 0x30039D1E, 0x21A1475B, 0xFD43D4DC, 0x33A72481, 0xCEDEF79C, 0x3A63C446,
    0xBA18115E, 0x30FA9A0E, 0x0D70B980, 0xDF6BF6B7, 0x10B42F72, 0xFB016F7E, 0x91D3082E, 0xA59E42DD,
    0x6E30FB19, 0x321737F1, 0x3009E00F, 0x21CEA5D7, 0x788046D0, 0x59F8A99A, 0xBAC444DB, 0x5724F3A5,
    0x86427171, 0xF7C02010, 0x1DD1B179, 0xFEFA165C, 0x908E98EB, 0xC4426E82, 0x40E3B44C, 0x434A6DCB,
    0xE1D30048, 0x400076E3, 0xA72B4BCA, 0xA06453F9, 0xC8C0587F, 0xF8D646BA, 0x9679B01B, 0x43BACCC8,
    0xC92C635E, 0x57D29704, 0x2CDF8FD5, 0x2937111D, 0x8678EA7C, 0xEB15A814, 0x362A59A6, 0xF0929C61,
    0x3C9C4D35, 0xA4613E57, 0x4D7236C2, 0xE8B36BFB, 0x5687CD76, 0x161BF8B6, 0xEF901EF8, 0x38F44734,
    0xC8518A6F, 0xA7B611AD, 0xA16966E6, 0xE0A5F109, 0x90CC6051, 0x7050646B, 0x189DCA33, 0x5FCC2216,
    0x0338F4FF, 0x37A315C9, 0x269F159B, 0x5B8F44DF, 0xB01A2206, 0x1036B4B5, 0xCE8BBC3D, 0x3D90344D,
    0xAB7384E3, 0x1DA0431D, 0xF4D675F0, 0x3605DF7C, 0x042CF7BF, 0xBB721034, 0x8B4351A1, 0x7CCDFF90,
    0x3077FCCC, 0x2BE599E6, 0x3F330325, 0x46CE60E5, 0xF21F7C09, 0x6D43FC1D, 0x1B770BBD, 0xAC82FEE5,
    0x78ADD8A7, 0xC22595A0, 0x3F1239A6, 0x2A03B602, 0x850263F6, 0x92BC209F, 0x78C3DDC1, 0xF701BB93,
    0xEAB125D5, 0xE9511EE8, 0x3E521432, 0xB7E9C3A3, 0x4DE31A56, 0x3837C001, 0x515976C3, 0xA83DE5EC,
    0x7F94CE6A, 0x7C272EC0, 0xA7097ABD, 0xA82F2686, 0x68613509, 0x9CE18247, 0xEB438F23, 0xC0052575,
    0x09C85A4A, 0xB412B611, 0x9CB9DEDE, 0x4C8FA8EC, 0xF333E5AE, 0xDE475EA6, 0xD0061EAA, 0x6E687B64,
    0x75083FF7, 0xF7112C92, 0x93408E2B, 0xEC1937E5, 0xE9AE251F, 0xF50728E2, 0xF958FD44, 0x550EBB4A,
    0x45190DB6, 0x3EA65E6E, 0xCA70F620, 0x7C27FD39, 0x94DADEAB, 0x6F37768E, 0x2DDE412F, 0x4729A062,
    0xA27173A7, 0x257226B0, 0xF58D2917, 0xF0AE6369, 0xBF017E01, 0x5BD06B80, 0xD5F1DC61, 0x8CC45ABF,
    0x69F7DA8C, 0x048FDB72, 0xA6CA5835, 0xA5C42498, 0x89A7E2DC, 0xC09C1A18, 0x62D301C2, 0xBAC7B0EA,
    0x0B74B61E, 0xCDFECF41, 0x2CEA8BBD, 0xB2503B05, 0xEDFF0D5E, 0x6D160C98, 0x7582CB39, 0x5F6F60EF,
    0xA63E5A5F, 0x0574BE6B, 0xF8696058, 0x7A5F57C3, 0x847315D8, 0x805FEB24, 0xA54D1571, 0x5E6DECE7,
    0x01F2A0EE, 0x8C69E934, 0x5D8BE7CB, 0x0FD2BAD5, 0x19CFEFD5, 0xF8C30676, 0xD83AD304, 0xD97DEAD7,
    0x149DBE02, 0xACA7D6D1, 0x1C83BEFD, 0x884BF0F4, 0x85A32394, 0xF78346BE, 0x5AA04532, 0x5D9AB6F0,
    0x84269010, 0x189C70C0, 0xCECDCD11, 0xF81A7F92, 0xE34D199D, 0x1801E718, 0xFFB09629, 0x923F5873,
    0x6FBEECC4, 0xD82221D3, 0xA34D67EF, 0x3704CF30, 0x472E4268, 0x940356FA, 0x8DB414D5, 0x99A0C7A3,
    0x7B222428, 0xE52340ED, 0x13B257DE, 0xF0A23A33, 0xB4F7E0E1, 0xA281FF29, 0x31B309D0, 0xC9BD3976,
    0x0D3DD1C6, 0x0331F819, 0xB59CDA2D, 0x349F455B, 0xEDAAD4A6, 0x11041E4E, 0x6CAEF794, 0x0411EBAD,
    0xBEC67FB0, 0xB8422981, 0xB570741B, 0x646BE3D5, 0x36234848, 0x11B68459, 0x285888FB, 0xAD76BCA5,
    0xD63F25A3, 0x56334527, 0x46973210, 0x8F152537, 0xC3BA78F8, 0xFEADF6E0, 0x1DD25885, 0x1DAE099A,
    0xC5207B45, 0xEDE2A9D0, 0x22A4A1D9, 0xEF588113, 0xC5341945, 0x7B819EBE, 0x0FAA41EE, 0x5804FBBB,
    0x2F308F01, 0xEEBEF944, 0x3BA79F89, 0x2AE12B76, 0x3D834308, 0xBDF524C5, 0x1D4DBE37, 0xCB46FA9B,
    0x169FF0C6, 0x4B1BB64C, 0xF94142FE, 0x6C5006F0, 0x04079883, 0xC31DB684, 0xAA7856A4, 0xBF19F480,
    0x2FE46BBC, 0x339857F5, 0xE1B694B5, 0x40F4314B, 0x4D237410, 0x9447F799, 0x09CBC597, 0xDD3C7740,
    0xA72412B7, 0x09CF1893, 0x8C0931FC, 0x89B9566C, 0x6CD6092B, 0x463A61D1, 0xCC7CC567, 0x02DA5412,
    0x8546CA77, 0xB9EAB343, 0x6AE83854, 0xDA7E1017, 0xB1CA3482, 0xDD943D56, 0x8D5E35C7, 0xFCA5F990,
    0xE5A16B15, 0x9C2CDE28, 0xC98FABFA, 0x6C445A9A, 0x2923040D, 0x21BCF35D, 0x784AAE95, 0xA27F3645,
    0x08FA0185, 0x56CEE3DB, 0x4CBB6A2A, 0xC7E466B5, 0xA5ECBD3B, 0xEFCC5F6E, 0x44AA4682, 0x6DD5A129,
    0xD4810B26, 0xF7396B92, 0x09B7EC75, 0xF92EE806, 0xB72D2C65, 0xD75CFC12, 0x93D5AD27, 0xE7FE372E,
    0x113CAA8F, 0x37461232, 0xAE8483FE, 0xA874E350, 0x6B3B0431, 0xBCB1E771, 0xEA4D1B93, 0xE838B800,
    0xB03191F5, 0x5870FA4E, 0x3477F93F, 0x0CC889BD, 0x477D3743, 0xC5830741, 0x3B8223D2, 0x3CC26590,
    0x02882CE9, 0xAEF8D76E, 0xF3BF5219, 0xBE7116FE, 0x365A44A1, 0x841ADC64, 0xE0D2A5BC, 0x8E6F7B68,
    0xD377CD8D, 0x5F5CC9BD, 0xF6A044F0, 0x5A085619, 0xCEF4D486, 0xA759491D, 0x9129FAC5, 0x10AF0C04,
    0x3B75C10B, 0xB9DA429E, 0xB05068E2, 0xB349CFD0, 0xE25E0C65, 0xD1773420, 0x21FA0FCA, 0x1317F898,
    0x3C34E1B1, 0x29CC00E2, 0x3CEB788F, 0xA7243BA4, 0xE25EAC49, 0x9DDB1C38, 0x27E6C700, 0x20B1E594,
    0x9D59AF63, 0xEF156BCA, 0x6DEE5BA4, 0x899DE0CA, 0x8C8BD682, 0xCE3B9EB8, 0x994A736C, 0xD7E57A6C,
    0x5CAD6057, 0x4E7A78E2, 0xD6131379, 0x7578143F, 0x76808B73, 0x87D726A9, 0x59721536, 0xAE948488,
    0x0CABE7D0, 0x2565DC12, 0x15E72950, 0x6049CB78, 0xB9553FE4, 0xF8B43FD9, 0x0E27E11D, 0x0156AC83,
    0x07E5B8C9, 0xC75EC675, 0xF473B995, 0xA659639F, 0x0A1E2CD7, 0x03DDBB2F, 0x5E35D87C, 0x938CA890,
    0x4FD15FD7, 0x40B7F3AA, 0x79CF6D4A, 0xE4794BC8, 0xDFC6679D, 0xDF8C70B0, 0xCE17B770, 0x4059F17C,
    0xD0EE15E6, 0xD870CFB1, 0xADB26268, 0x9A9CC235, 0x74FE26C9, 0xC34EF110, 0x760B8D57, 0x4552E8A3,
    0x2C43B0A6, 0x350CA735, 0x946AC151, 0x48FE3E8E, 0xE5E261BF, 0xD257DE9A, 0x0576E8DB, 0xCC884E89,
    0x2634AE5F, 0xB87803BD, 0x8DB8468F, 0x1121AABE, 0xE60F550B, 0xB96BF8F3, 0x3B8B0C59, 0x24D6E38F,
    0x8BAEB201, 0x1EAAD88E, 0xB1C32121, 0x19AD7041, 0x1064FA95, 0xF1036230, 0x3BFA2CC4, 0x8DB395EC,
    0xF87BE9C8, 0x74795B99, 0x79C09757, 0x6EF57972, 0x96585340, 0x521DF397, 0xFA6E6BCF, 0x1A6DE329,
    0x0E36C46B, 0x5E075D1F, 0xE0E8ABB5, 0x7C52BD73, 0xEECAC0BD, 0x3934CA2F, 0x3F8E15AC, 0x31C86251,
    0xD43FA0BA, 0xF31E68E8, 0x51E350F0, 0xC81BBE61, 0xD124891B, 0x7E4959F3, 0x035867FB, 0x6969FAFA,
    0xAEE5D71B, 0xCEE0AB78, 0x01ACEDD5, 0x790CD214, 0x569BDB94, 0x4E7199BE, 0x8F87F74A, 0x032F2F12,
    0x7208FE83, 0xA7AA1596, 0xC098242A, 0x78A91D1C, 0x8AF45BC3, 0xD1A0D8CC, 0x88E877CE, 0xAA645FE4,
    0x16ED8744, 0x593440B9, 0xA14901F1, 0x7BD3CA7E, 0xEAAEC7E5, 0xB9F23B79, 0xC51DB24C, 0x7750F8ED,
    0xD1AB5760, 0x2A09DF5B, 0xC034E567, 0x046165D0, 0x38E46344, 0x004F2200, 0x4AE5FFE3, 0xCFDF63B7,
    0x16B08DB5, 0x7ADEAE1D, 0xA49386F7, 0x2BEAB1A7, 0x3591F2B9, 0x807564A3, 0xE363DC0F, 0x5EA1486F,
    0xD51BBEE1, 0x86CE6B67, 0x64381877, 0xE6474C06, 0x95C84264, 0x97E7A80C, 0x51E93437, 0x097158F0,
    0xF6938D3A, 0x63878A29, 0x8C3DCEB4, 0x6B9FFCB5, 0x34CC55EB, 0x56A2A4EE, 0xF9A81741, 0x164E49D4,
    0x06F71A4B, 0x52211B45, 0xC96913FB, 0xDC7961C5, 0xE16726D8, 0x5C410904, 0xE3AAB836, 0x21B2A55D,
    0x50C11664, 0x7839ADC6, 0x8FCFA43A, 0x71CED992, 0xE14A4394, 0x2D143A84, 0x8DAC67E9, 0x2EC7A274,
    0x761D1FC7, 0xF2DE7C12, 0x159DF8A8, 0x0C7E2166, 0xB1E440DE, 0xFF04F20D, 0x4EECCC33, 0x0A01A4FF,
    0xC96D049E, 0x30889B7D, 0xE57AC9A7, 0x2798E0D1, 0x1B692B28, 0x75A0D742, 0x9CB52890, 0x939FA911,
    0x06A778F9, 0xA0BA1ECA, 0x24E34C6F, 0x45A5673D, 0xDC834BB3, 0xD2E4BAB5, 0x131E5A8D, 0xD7E7C4D3,
    0x9EB24CFC, 0xC655E386, 0x7582C229, 0x4D5D786C, 0x7F59684E, 0xDF843B2F, 0x84ECD02C, 0x68B08D2B,
    0xDB0A0809, 0x939B33E5, 0xA9E52141, 0x7848F78B, 0x3B0EAB7D, 0xB01460E3, 0xFF944DEE, 0xA4EDC6CF,
    0x6B9CF0BB, 0xBF54AD44, 0x89230009, 0x4466067E, 0xE731AABB, 0xAF123ECA, 0xCD8C864F, 0xFDA366CF,
    0x2DC304FF, 0xF7EEB8A1, 0x553A7C55, 0x484C6C14, 0x19E60ADC, 0x0582839C, 0x4B6BE54C, 0x48EB5BB6,
    0xB251DDEA, 0xEFCA0E72, 0xAA590C93, 0x8845A53E, 0x71467E21, 0x76103879, 0x67820E2C, 0x933760FA,
    0x30C218AC, 0x7935B725, 0x097C0ACC, 0xED19FFD3, 0x7D68291E, 0x69A242D3, 0x99053262, 0x585E62E8,
    0x69591441, 0xD5FADE92, 0x40353B78, 0x0EB3C38D, 0x88D305EA, 0xE4806EDD, 0xAE0D741B, 0x162B4955,
    0xCF354CC8, 0x86B6AA01, 0xDFCC156C, 0x08A3D03B, 0x3EBF1197, 0x23CB4B43, 0xC2A9EB0F, 0x5999D3BF,
    0x8EF8C1A0, 0x9F6D747A, 0xFEAD2B29, 0xC38F8EAC, 0xF65C7347, 0x57D667C5, 0xD95F495B, 0x77870865,
    0xE27A28E9, 0x26AE3EC6, 0x303D6267, 0x608AF015, 0x8013DCA9, 0xBE6C9AB2, 0x21704C40, 0x0BF3A774,
    0x348594FD, 0xDAA81B81, 0x43ED9D03, 0x4980FDCC, 0x54DCC71E, 0x97192D23, 0x0003A01A, 0x0A7B91B9
};
```
