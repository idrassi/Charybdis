### **Charybdis Block Cipher**

**Author:** Mounir IDRASSI <mounir.idrassi@amcrypto.jp>
**Date:** June 15, 2025
**Version:** 1.0
**License:** CC0 1.0 Universal (Public Domain Dedication)

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
*   **State Matrix:** The 512-bit internal state `S` is represented as a `4×4` matrix of words. The matrix is populated from an input block in row-major order, i.e., `S[i][j]` corresponds to word at byte positions `16*i + 4*j` through `16*i + 4*j + 3`.
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
This operation XORs a unique 32-bit constant into each of the 16 words of the state in every round. This design aims to break structural and inter-round symmetries.

*   **Constant Generation:** The 352 (22 rounds × 16 words) 32-bit constants (`RC`) are generated using SHAKE256.
    1.  **Input Seed:** The input to SHAKE256 is the 14-byte ASCII sequence `"Charybdis-v1.0"` (without null terminator):
        ```
            0x43 0x68 0x61 0x72 0x79 0x62 0x64 0x69 0x73 0x2D 0x76 0x31
            0x2E 0x30
        ```
    2.  **SHAKE256 Invocation:** SHAKE256 is applied to produce a 1408-byte output stream.
    3.  **Output Parsing:** The 1408-byte stream is parsed into 352 consecutive 32-bit words. Each 4-byte chunk is interpreted using **big-endian** byte order: bytes `B0, B1, B2, B3` become `(B0 << 24) | (B1 << 16) | (B2 << 8) | B3`.

*   **Operation:** For round `r` (1 to 22), and for `i,j` from 0 to 3:
    `S[i][j] ← S[i][j] ⊕ RC[(r-1)×16 + (4×i+j)]`
*   **Inverse:** The operation is self-inverse.

```c
// Round Constants (RC) for 22 rounds
static const uint32_t RC[352] = {
    0x09ABE449, 0x3DDB6251, 0xC380C165, 0x7C7C336B, 0xC2E84709, 0x2822540C, 0xB1292CBD, 0x35C10D58,
    0x364A2099, 0x02D8C517, 0x2E8400A4, 0x3CE2C4E9, 0x28D42EC1, 0x68B5DAA2, 0xBB07BE9E, 0x13858972,
    0xFD006DF7, 0x4B796F9C, 0x4FD45A7D, 0x9262B547, 0x3D5A02E6, 0x2007F8ED, 0xF157C620, 0x2B169543,
    0x9065E406, 0x936651BC, 0x263E092C, 0x168567B1, 0xE9282CE7, 0x6AE805DD, 0x9512D3AE, 0x77D6C340,
    0x77D87F83, 0xBA5019B6, 0xA4074C67, 0xF779426B, 0x2BB79CE6, 0xDC0947BE, 0x155328B4, 0xE913C7D7,
    0x543BEB4A, 0xD811E60E, 0xEB7EDD89, 0x63442F04, 0x2F13CA7F, 0x96902BC1, 0xE130CE64, 0x2CF515C7,
    0x03AA4951, 0x80580C51, 0x4AB3D97B, 0xE7590DC0, 0xFFBB6B73, 0x0F0F6706, 0x64752E03, 0xFA5FBCB2,
    0x7C190F62, 0x458908F3, 0xE9E362E3, 0x7BDE6448, 0x5A66A533, 0xDFB24DF3, 0xCC2B3821, 0x5FA39BB4,
    0x4F73277D, 0x5611DBA6, 0xF14AECF2, 0xF6D20F69, 0x09A84AF5, 0x2A127A24, 0x81432785, 0x7F343AD1,
    0x1756EBAC, 0xE9E30A59, 0xE3FACC57, 0xF10A06D1, 0xAF0E0EC4, 0xCA4D5A54, 0x3F6FACB8, 0x665498B0,
    0x215156DD, 0x19ED1BE1, 0xAE7147F1, 0xBE1AADD7, 0xA28FB4D8, 0xB3AC541D, 0xA987333C, 0x87D35536,
    0xCB688C94, 0x8CF3949F, 0xC0FBB4F0, 0xC0D2B91E, 0xC8982223, 0x3C429565, 0xA7560614, 0x202A030D,
    0xF53AF63A, 0xE43A8DDB, 0x5E2E575E, 0xDD57DFC8, 0x8C112ED6, 0x4CEA7366, 0x7B06DD82, 0x51A0B67E,
    0x25AA2519, 0x1A1B9913, 0x15A06D28, 0x9503619E, 0x8F041BB2, 0x8EBB01DF, 0xD210A991, 0x3A590439,
    0x94F13D92, 0xD3C3A42A, 0x07B2D92A, 0x450D4F51, 0xCBE6B134, 0x90737167, 0xC95EA7EB, 0x61AC9406,
    0x5D97C1D5, 0x7501BB29, 0x434DA233, 0x9066A57A, 0xB9192FB4, 0x81F1A972, 0x6D39D67A, 0xCC8CACEB,
    0x621744A2, 0xDBAAB4FB, 0xBE2F3851, 0x6488CA8F, 0x0FF92C9B, 0x515DE568, 0x59199265, 0xD3FAB509,
    0xA8E9B6FA, 0xD52A5B51, 0x3F72D930, 0x6AB7AE55, 0xF04113DA, 0x97E051E1, 0xCE88E7C7, 0xF4A0F228,
    0x4D9C3A41, 0x7719C6CE, 0x5180FD62, 0x9FBBE2ED, 0x3447B35D, 0xDB7770E8, 0x360DA146, 0x13F2949B,
    0xDC7DD59A, 0xE0D81339, 0xE32D84E7, 0x85E3620A, 0x2DA0DAC5, 0xCFC55BC5, 0x7C07B0D7, 0x2B657CC5,
    0x2EB0B633, 0xC6A1BF8B, 0x602F04CD, 0x1D8DD0BC, 0x8543F65F, 0x811B9066, 0xBD869790, 0x00542D3C,
    0x778B7CF0, 0xB2393E66, 0xCF04ACC8, 0xD62777BC, 0xDE65FC5E, 0xD57E1734, 0x986C0E52, 0x3EDCBE4C,
    0xD48FDBA7, 0xE9C9AB85, 0xE2160D86, 0x848BCD2E, 0xF61173CE, 0x8527CA20, 0x1AF3BDD3, 0x25F161F4,
    0x30BD9755, 0xF10FE177, 0xBB0E2976, 0xBAD3A975, 0x0033D3AF, 0x870750BD, 0x12A8D47C, 0xA5825356,
    0xF5959E2C, 0x8151B51B, 0x6862DE73, 0xBB312C3C, 0x9E5355BF, 0x72ED4D18, 0x7E4CC18D, 0x719F2BE5,
    0x27F33D1C, 0x22A486CE, 0x84389409, 0x48168978, 0xFD079DC5, 0x75814C40, 0x8E9F941F, 0x13DEA9F0,
    0xAB7C7DE2, 0x16452A73, 0x06E33C9C, 0x1C3F6D1F, 0x4EFABDBF, 0xF2750B69, 0xCCE8A407, 0x0EAD6C92,
    0xF765A5B8, 0x4ED5AA31, 0xD8EAC691, 0xDFE2984C, 0x0349D1FB, 0x4D67DC84, 0x5398E1FA, 0xDE29EEEE,
    0x38F366B4, 0x68CA2C8B, 0xC1B3BED2, 0x041BFCBD, 0x3E3E6204, 0x696C2C63, 0xB41FC6CE, 0xEE229514,
    0x48988B17, 0xB995E9C3, 0x658A8D9A, 0x055EA378, 0xB904E1CB, 0xCD5FEEB3, 0x03B91E48, 0xFD75CF21,
    0x5BA6E8AD, 0x7DF9F99F, 0x306F14AF, 0x87F5EB0C, 0x396BD2A2, 0xF7599C23, 0xBE8570C5, 0xC9B64ADD,
    0xC3928B1D, 0x04436D28, 0xF8F7910C, 0x6A7846D2, 0x5FC307F0, 0x40465DC0, 0x90445674, 0xE42870AC,
    0xBB17B82B, 0x853381EC, 0xDC9B9F18, 0xA99C6476, 0x1194616E, 0xCA3C8B06, 0x6DC6F322, 0x17A3F18C,
    0x2BFC1E98, 0x9C2DA3BF, 0x4ACC14B4, 0xDF0DFDE4, 0x5958A8F2, 0x2CA073FC, 0x4791B19F, 0x1094CEC2,
    0xDC476A57, 0x9CF2B91D, 0xCE9FA41C, 0x4C4DDC5F, 0x2657F8B9, 0xBD70AA92, 0x65AABD79, 0x2D269C1D,
    0x4C141B65, 0x67A9533D, 0xF8919053, 0x05AAA3AF, 0x6D844A3A, 0xE3422F83, 0x569C246B, 0x93BCD2D5,
    0xF803C8C4, 0x498A7C16, 0xF990BE9D, 0x83E16722, 0x64E079AC, 0x073F1607, 0x70733F3A, 0x8F579AD0,
    0xD95DD747, 0x1E2FB545, 0x24A25404, 0xE0269BA9, 0xCD0A4CB2, 0xB3A1A142, 0x38C9DE48, 0x804629DE,
    0x0FFB734E, 0x23E8F5C7, 0x975EFFC3, 0xCC69CA57, 0x6F72BCF4, 0xCDFA14A4, 0xBA5D6DF2, 0xB75D44E4,
    0x0B6C3002, 0xF22F5A5F, 0xEF66B79E, 0x56456B1B, 0xDA9B3759, 0x67092DFD, 0x6D21A8D9, 0xC002A278,
    0x27DBF77A, 0x6F9DB625, 0x30C622AF, 0x72EFB64E, 0x7783D27C, 0x7ADEA18A, 0xE032424A, 0x910E0FD5,
    0x8E2112F8, 0xE4278E2C, 0x63401CEA, 0x710E3EDC, 0x3C83A7F8, 0xA4D5FB9A, 0xAD4BD798, 0xD5B1C72E,
    0xA49F63A0, 0x4C020B00, 0xA0502BC6, 0xED5690F7, 0xDEE33D1B, 0xE99EA2BF, 0x7E29ACBF, 0x5CFED974,
    0x4DE5601D, 0x68429B27, 0xBBD6B951, 0x371F8DC8, 0xDE8BEC28, 0x3865E536, 0x43D7A05D, 0xBC731F08
};
```

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
*   **Constants:** The initialization constants (`C_INIT`) and the key schedule permutation's round constants (`RC_F`) are generated using SHAKE256 for transparency and to avoid weak constants.

##### **Constant Generation Procedure**

1.  **Input Seed:** The input to SHAKE256 is the 24-byte ASCII sequence `"Charybdis-Constants-v1.0"` (without null terminator):
    ```
        0x43 0x68 0x61 0x72 0x79 0x62 0x64 0x69 0x73 0x2D 0x43 0x6F
        0x6E 0x73 0x74 0x61 0x6E 0x74 0x73 0x2D 0x76 0x31 0x2E 0x30
    ```
2.  **SHAKE256 Invocation:** SHAKE256 is applied to produce a 352-byte output stream.
3.  **Output Parsing:** The 352-byte stream is processed sequentially. Each 4-byte chunk is interpreted using **big-endian** byte order: bytes `B0, B1, B2, B3` become `(B0 << 24) | (B1 << 16) | (B2 << 8) | B3`.
    *   **`C_INIT` Generation:** The first 96 bytes (24 words) populate `C_INIT[0]` to `C_INIT[23]`.
    *   **`RC_F` Generation:** The subsequent 256 bytes (64 words) populate `RC_F[0]` to `RC_F[63]`.

Compliant implementations **MUST** use the following pre-computed values, which can be verified using the procedure above.

```c
// Initialization constants (C_INIT) for the key schedule state (KSS)
static const uint32_t C_INIT[24] = {
    0xBD9A3A61, 0xD84F43D2, 0x8194DFDE, 0x5CB04029, 0x22A7C7A9, 0x4F096DED, 0x785F4AC0, 0xEAD4D3BE,
    0x24132CEB, 0x3C26A408, 0x0E8ABAB4, 0xC4EAF2E0, 0x30F98C45, 0x68AAC99C, 0x1B0F630C, 0xE3C7E561,
    0x19D05E5C, 0xC042E4D5, 0x4797EB1B, 0xDEF00CA6, 0x62DB6702, 0xC6A9C3A5, 0x0ACCD1EF, 0xD1C8BCCA
};

// Key schedule permutation round constants (RC_F) for 16 rounds
static const uint32_t RC_F[64] = {
    0x3E98EF87, 0x4BCE334C, 0xD168DED4, 0x85E3E548,
    0xCA398279, 0xBD7942AA, 0xA6190439, 0x47EFBB5C,
    0x8C355F74, 0xE80218A6, 0x71782BC0, 0x90BE95DE,
    0x99DE60E1, 0x4CB3B234, 0xD00767B7, 0x6F859650,
    0x12F7221D, 0x5AB799D8, 0x88A9026E, 0xDC16FD26,
    0xEA2DC5C2, 0x4FFB7C63, 0x4DDF1E6F, 0xCF17F3CB,
    0x3F12E663, 0x22E33B11, 0x1E1BD097, 0x10DEB2F9,
    0x53E3FB3B, 0xAC19AE00, 0xD4229837, 0xFC808D4F,
    0xEE33C798, 0xC3CA41BB, 0x8EEFA083, 0xE3841110,
    0x753A29FB, 0x77D08286, 0x20D96B4B, 0x1D1E520F,
    0xD0C1B4D9, 0xFB52AB02, 0x822BA801, 0xAB605DE0,
    0xE4628371, 0xA703DC62, 0x26EEF620, 0x545680F7,
    0x79AF2D28, 0x85A19B6A, 0xC7D674CC, 0x75E459A9,
    0xC0DC0A33, 0x8D74272B, 0x328404A5, 0x6E4CD691,
    0xCEE8EBED, 0x2F254E8B, 0x1A27665A, 0x51A39984,
    0xB049AA63, 0xB529877B, 0x0DB026E9, 0x89C62BC4
};
```

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
1.  **Initialization:** The 1024-bit `KSS` is loaded with `M` (256 bits) in the first 8 words and `C_INIT` (768 bits) in the remaining 24 words. The master key `M` is placed in `KSS[0][0]` through `KSS[0][7]` in big-endian word order. The constants `C_INIT[0]` through `C_INIT[23]` are placed in `KSS[1][0]` through `KSS[3][7]`.
2.  **Absorption:** `F_perm(KSS)` is called once.
3.  **Squeezing:** For `i` from 0 to 23:
    a.  **Squeeze:** Subkey `K[i]` is extracted from the rate part of `KSS` (the leftmost 4×4 portion: `KSS[0][0]` through `KSS[3][3]`).
    b. **Permute (if i < 23):** To provide domain separation between subkey generations, inject counter `(i + 1)` and apply permutation:

        *   `KSS[0][7] += (i + 1)`
        *   `KSS[1][3] += (i + 1)`
        *   `KSS[2][6] += (i + 1)`
        *   `KSS[3][1] += (i + 1)`

        After the counter injection, call `F_perm(KSS)`.

---

### **6. Design Rationale**

Charybdis is based on conservative and well-studied cryptographic principles:

*   **Classical SPN Structure:** The round function `SubConstants → ColumnMix → ShiftRows → AddRoundKey` follows a well-analyzed structure. This design aims to make the properties of the non-linear layer independent of key material, potentially simplifying security analysis and defending against key-dependent attacks.

*   **Symmetry Breaking:** The `SubConstants` layer applies unique constants to the entire 512-bit state in every round. This approach, used in modern cipher designs, aims to defend against structural attacks such as slide, rotational, and invariant subspace cryptanalysis by ensuring no two rounds have identical transformations.

*   **Diffusion Strategy:** The combination of `ColumnMix` (designed for strong intra-column ARX diffusion) and `ShiftRows` (optimal inter-column permutation) aims to provide rapid and full diffusion. The 22-round count is chosen to provide a security margin against differential and linear cryptanalysis.

*   **Key Schedule Design:**
    *   **Permutation Security:** The internal permutation `F_perm` uses 16 rounds, chosen to provide a security margin against potential distinguishing attacks on the permutation itself. This design aims to help the 512-bit capacity of the sponge construction achieve a 256-bit security level.
    *   **Component Separation:** The use of a distinct permutation (`F_perm`) with different rotation constants for the key schedule is a deliberate design choice. It aims to cryptographically separate the key schedule from the main cipher, potentially preventing attacks that leverage properties from one component against the other.

---

### **7. Test Vectors**

A compliant implementation **MUST** produce the following values from the given inputs. All values are hex-encoded strings.

**Key (`M`):**
`000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F`

**Plaintext (`P`):**
`00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF`

**(Reference) Subkey `K[1]`:**
`9D7C90F475010C0CA80B57A170B193C0D48094454811E485141AA2ACAC327A2280A7A11E35C471DBB232BBDCB22767B82E8300F0F0A14F6200CE54622E92008A`

**(Reference) State `S` after Round 1:**
`4FEA17F3766C16357AD75F4BAF927AD8CC87C549DBA5E578E0F4A6F4C021982321956AA4B3D7A0EC80F1F6BB37FDEB8AE2F4022F02A3DEE911F3130FE815D2D8`

**Ciphertext (`C`):**
`CF669FE881E4E244A483B7E43FEFB0616A2117AB7D1C3CCBB90D1AFBF87545AD84D77152DBBC378904FA1525064FE7C1C22CC93C477C9B2EB80F382C40B3211B`

---

### **8. Implementation Notes**
- All multi-byte values (plaintext, ciphertext, keys, subkeys) are processed in **big-endian** byte order when converting between byte arrays and 32-bit words.
- The state matrix `S[4][4]` is populated from a 64-byte input block in row-major order: bytes 0-3 become `S[0][0]`, bytes 4-7 become `S[0][1]`, etc.
