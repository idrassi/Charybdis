/*
 * Charybdis Block Cipher - Reference Implementation
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
#ifdef _WIN32
#include <windows.h>
#endif
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "charybdis.h"
#include "charybdis_avx2.h"

/* Rotation macros */
#define ROTL(x,n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

/* --- Round Constants (CHARYBDIS_RC) for 22 rounds * 16 words = 352 --- */
const uint32_t CHARYBDIS_RC[352] = {
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

/* --- Key-schedule constants --- */
static const uint32_t C_INIT[24] = {
    0xBD9A3A61, 0xD84F43D2, 0x8194DFDE, 0x5CB04029, 0x22A7C7A9, 0x4F096DED, 0x785F4AC0, 0xEAD4D3BE,
    0x24132CEB, 0x3C26A408, 0x0E8ABAB4, 0xC4EAF2E0, 0x30F98C45, 0x68AAC99C, 0x1B0F630C, 0xE3C7E561,
    0x19D05E5C, 0xC042E4D5, 0x4797EB1B, 0xDEF00CA6, 0x62DB6702, 0xC6A9C3A5, 0x0ACCD1EF, 0xD1C8BCCA
};
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

/* --- ARX parameters for ColumnMix --- */
#define R1 13
#define R2 19
#define R3 23
#define R4 29
#define RH1 9
#define RH2 17
#define RH3 21
#define RH4 27

/* Core G and H and their inverses */
static void G_Mix(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *a += *b; *d ^= *a; *d = ROTR(*d, R1);
    *c += *d; *b ^= *c; *b = ROTR(*b, R2);
    *a += *b; *d ^= *a; *d = ROTR(*d, R3);
    *c += *d; *b ^= *c; *b = ROTR(*b, R4);
}
static void InverseG_Mix(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *b = ROTL(*b, R4) ^ *c; *c -= *d;
    *d = ROTL(*d, R3) ^ *a; *a -= *b;
    *b = ROTL(*b, R2) ^ *c; *c -= *d;
    *d = ROTL(*d, R1) ^ *a; *a -= *b;
}
static void H_Mix(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *a += *b; *d ^= *a; *d = ROTR(*d, RH1);
    *c += *d; *b ^= *c; *b = ROTR(*b, RH2);
    *a += *b; *d ^= *a; *d = ROTR(*d, RH3);
    *c += *d; *b ^= *c; *b = ROTR(*b, RH4);
}
static void InverseH_Mix(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *b = ROTL(*b, RH4) ^ *c; *c -= *d;
    *d = ROTL(*d, RH3) ^ *a; *a -= *b;
    *b = ROTL(*b, RH2) ^ *c; *c -= *d;
    *d = ROTL(*d, RH1) ^ *a; *a -= *b;
}

/* ColumnMix on a single 4-word column */
static void ColumnMixColumn(uint32_t col[4]) {
    G_Mix(&col[0], &col[1], &col[2], &col[3]);
    H_Mix(&col[0], &col[1], &col[2], &col[3]);
    H_Mix(&col[2], &col[3], &col[0], &col[1]);
    G_Mix(&col[2], &col[3], &col[0], &col[1]);
}
static void InverseColumnMixColumn(uint32_t col[4]) {
    InverseG_Mix(&col[2], &col[3], &col[0], &col[1]);
    InverseH_Mix(&col[2], &col[3], &col[0], &col[1]);
    InverseH_Mix(&col[0], &col[1], &col[2], &col[3]);
    InverseG_Mix(&col[0], &col[1], &col[2], &col[3]);
}

/* ShiftRows / InverseShiftRows */
static const int SHIFTS[4] = { 0,1,2,3 };
static void ShiftRows(uint32_t S[4][4]) {
    int i,j;
    for (i = 0; i < 4; i++) {
        uint32_t tmp[4] = {
            S[i][0], S[i][1], S[i][2], S[i][3]
        };
        for (j = 0; j < 4; j++) S[i][j] = tmp[(j + SHIFTS[i]) & 3];
    }
}
static void InverseShiftRows(uint32_t S[4][4]) {
    int i, j;
    for (i = 0; i < 4; i++) {
        uint32_t tmp[4] = {
            S[i][0], S[i][1], S[i][2], S[i][3]
        };
        for (j = 0; j < 4; j++) S[i][j] = tmp[(j - SHIFTS[i] + 4) & 3];
    }
}

/* AddRoundKey (XOR) */
static void AddRoundKey(uint32_t S[4][4], const uint32_t K[4][4]) {
    int i, j;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            S[i][j] ^= K[i][j];
        }
    }
}

/* SubConstants (and inverse is identical) */
static void SubConstants(uint32_t S[4][4], int round) {
    int base = (round - 1) * 16;
    int i, j;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            S[i][j] ^= CHARYBDIS_RC[base + 4 * i + j];
        }
    }
}

/* One forward round, one inverse round */
static void Round(uint32_t S[4][4], const uint32_t K[4][4], int r) {
    int j, i;
    uint32_t col[4];
    
    SubConstants(S, r);
    for (j = 0; j < 4; j++) {
        col[0] = S[0][j];
        col[1] = S[1][j]; 
        col[2] = S[2][j];
        col[3] = S[3][j];
        ColumnMixColumn(col);
        for (i = 0; i < 4; i++) S[i][j] = col[i];
    }
    ShiftRows(S);
    AddRoundKey(S, K);
}

static void InverseRound(uint32_t S[4][4], const uint32_t K[4][4], int r) {
    int j, i;
    uint32_t col[4];
    
    AddRoundKey(S, K);
    InverseShiftRows(S);
    for (j = 0; j < 4; j++) {
        col[0] = S[0][j];
        col[1] = S[1][j];
        col[2] = S[2][j]; 
        col[3] = S[3][j];
        InverseColumnMixColumn(col);
        for (i = 0; i < 4; i++) S[i][j] = col[i];
    }
    SubConstants(S, r);
}

/* Big-endian helpers */
static uint32_t load_be32(const uint8_t* b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}
static void store_be32(uint8_t* b, uint32_t v) {
    b[0] = v >> 24; b[1] = v >> 16; b[2] = v >> 8; b[3] = v;
}

/* --- Key schedule permutation F_perm --- */
#define F_R1 11
#define F_R2 19
#define F_R3 23
#define F_R4 29
static void F_G_Mix(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *a += *b; *d ^= *a; *d = ROTR(*d, F_R1);
    *c += *d; *b ^= *c; *b = ROTR(*b, F_R2);
    *a += *b; *d ^= *a; *d = ROTR(*d, F_R3);
    *c += *d; *b ^= *c; *b = ROTR(*b, F_R4);
}
static void F_perm_Round(uint32_t KSS[4][8], int r) {
    int i, j;
    for (i = 0; i < 4; i++) KSS[i][i] += RC_F[r * 4 + i];
    for (j = 0; j < 8; j++) F_G_Mix(&KSS[0][j], &KSS[1][j], &KSS[2][j], &KSS[3][j]);
    for (i = 0; i < 4; i++) {
        F_G_Mix(&KSS[i][(i + 0) % 8], &KSS[i][(i + 1) % 8], &KSS[i][(i + 2) % 8], &KSS[i][(i + 3) % 8]);
        F_G_Mix(&KSS[i][(i + 4) % 8], &KSS[i][(i + 5) % 8], &KSS[i][(i + 6) % 8], &KSS[i][(i + 7) % 8]);
    }
}

static void F_perm(uint32_t KSS[4][8]) {
    int r;
    for (r = 0; r < 16; r++) F_perm_Round(KSS, r);
}

/* Charybdis_KeySchedule: expand 256-bit master key to 24 × 512-bit subkeys */
void Charybdis_KeySchedule(const uint8_t master_key[32], uint32_t subkeys[24][4][4]) {
    uint32_t KSS[4][8];
    int j, i;
    
    /* Row 0 ← master_key (8 words) */
    for (j = 0; j < 8; j++) KSS[0][j] = load_be32(master_key + 4 * j);
    /* Rows 1–3 ← C_INIT (24 words) */
    for (i = 1; i < 4; i++) {
        for (j = 0; j < 8; j++) {
            KSS[i][j] = C_INIT[(i - 1) * 8 + j];
        }
    }
    /* Absorb */
    F_perm(KSS);
    /* Squeeze 24 subkeys */
    for (i = 0; i < 24; i++) {
        int r, c;
        for (r = 0; r < 4; r++) {
            for (c = 0; c < 4; c++) {
                subkeys[i][r][c] = KSS[r][c];
            }
        }
        if (i < 23) {
            KSS[0][7] += (i + 1);
            KSS[1][3] += (i + 1);
            KSS[2][6] += (i + 1);
            KSS[3][1] += (i + 1);
            F_perm(KSS);
        }
    }
}

/* Encrypt one 64-byte block */
void Charybdis_EncryptBlock(const uint8_t in[64], uint8_t out[64],
    const uint32_t subkeys[24][4][4]) {
    uint32_t S[4][4];
    int i, j, r;
    
    /* Initial whitening */
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            S[i][j] = load_be32(in + 4 * (4 * i + j)) ^ subkeys[0][i][j];
        }
    }
    /* 22 main rounds */
    for (r = 1; r <= 22; r++) Round(S, subkeys[r], r);
    /* Final whitening */
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            S[i][j] ^= subkeys[23][i][j];
        }
    }
    /* Store output */
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            store_be32(out + 4 * (4 * i + j), S[i][j]);
        }
    }
}

/* Decrypt one 64-byte block */
void Charybdis_DecryptBlock(const uint8_t in[64], uint8_t out[64],
    const uint32_t subkeys[24][4][4]) {
    uint32_t S[4][4];
    int i, j, r;
    
    /* Initial state */
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            S[i][j] = load_be32(in + 4 * (4 * i + j)) ^ subkeys[23][i][j];
        }
    }
    /* Inverse rounds */
    for (r = 22; r >= 1; r--) InverseRound(S, subkeys[r], r);
    /* Final whitening */
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            S[i][j] ^= subkeys[0][i][j];
        }
    }
    /* Store output */
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            store_be32(out + 4 * (4 * i + j), S[i][j]);
        }
    }
}

void charybdis_clear(charybdis_context_t* ctx) {
    if (ctx) {
        charybdis_secure_memzero(ctx, sizeof(charybdis_context_t));
    }
}

/* =============================================================================
 * SELF-TEST AND BENCHMARKING
 * ============================================================================= */

#ifdef BENCHMARK
#include <time.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#define rdtsc __rdtsc
#else
#include <sys/time.h>
#include <unistd.h>
static inline uint64_t rdtsc(void) {
    uint32_t hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}
#endif

/* High-resolution timing */
static double get_time_seconds(void) {
#ifdef _WIN32
    static LARGE_INTEGER freq = {0};
    LARGE_INTEGER counter;
    if (freq.QuadPart == 0) {
        QueryPerformanceFrequency(&freq);
    }
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart / (double)freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
#endif
}

/* CPU frequency estimation */
static double estimate_cpu_frequency(void) {
    uint64_t start_cycles = rdtsc();
    double start_time = get_time_seconds();
    
    /* Sleep for 10ms for measurement */
#ifdef _WIN32
    Sleep(10);
#else
    usleep(10000);
#endif
    
    uint64_t end_cycles = rdtsc();
    double end_time = get_time_seconds();
    
    double elapsed_time = end_time - start_time;
    uint64_t elapsed_cycles = end_cycles - start_cycles;
    
    return (double)elapsed_cycles / elapsed_time;
}

/* Benchmark configuration */
typedef struct {
    size_t nblocks;
    int iterations;
    int warmup_iterations;
    double cpu_freq_ghz;
} benchmark_config_t;

/* Benchmark results */
typedef struct {
    double min_time;
    double avg_time;
    double max_time;
    uint64_t min_cycles;
    uint64_t avg_cycles;
    uint64_t max_cycles;
    double throughput_mbps;
    double cycles_per_byte;
} benchmark_result_t;

/* Generate random test data */
static void generate_random_data(uint8_t* data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        data[i] = (uint8_t)(rand() & 0xFF);
    }
}

/* Benchmark reference implementation */
static benchmark_result_t benchmark_reference_encrypt(const benchmark_config_t* config) {
    benchmark_result_t result = {0};
    const size_t data_size = config->nblocks * CHARYBDIS_BLOCK_SIZE;
    
    /* Allocate aligned buffers */
    uint8_t* plaintext = (uint8_t*)malloc(data_size);
    uint8_t* ciphertext = (uint8_t*)malloc(data_size);
    uint8_t key[CHARYBDIS_KEY_SIZE];
    uint32_t subkeys[CHARYBDIS_SUBKEYS][4][4];
    
    if (!plaintext || !ciphertext) {
        printf("Memory allocation failed\n");
        free(plaintext);
        free(ciphertext);
        return result;
    }
    
    /* Generate random test data */
    generate_random_data(key, CHARYBDIS_KEY_SIZE);
    generate_random_data(plaintext, data_size);
    
    /* Expand key */
    Charybdis_KeySchedule(key, subkeys);
    
    /* Warmup */
    for (int i = 0; i < config->warmup_iterations; i++) {
        for (size_t j = 0; j < config->nblocks; j++) {
            Charybdis_EncryptBlock(plaintext + j * CHARYBDIS_BLOCK_SIZE,
                                 ciphertext + j * CHARYBDIS_BLOCK_SIZE,
                                 subkeys);
        }
    }
    
    /* Benchmark */
    result.min_time = 1e9;
    result.max_time = 0;
    result.min_cycles = UINT64_MAX;
    result.max_cycles = 0;
    double total_time = 0;
    uint64_t total_cycles = 0;
    
    for (int i = 0; i < config->iterations; i++) {
        uint64_t start_cycles = rdtsc();
        double start_time = get_time_seconds();
        
        for (size_t j = 0; j < config->nblocks; j++) {
            Charybdis_EncryptBlock(plaintext + j * CHARYBDIS_BLOCK_SIZE,
                                 ciphertext + j * CHARYBDIS_BLOCK_SIZE,
                                 subkeys);
        }
        
        double end_time = get_time_seconds();
        uint64_t end_cycles = rdtsc();
        
        double elapsed_time = end_time - start_time;
        uint64_t elapsed_cycles = end_cycles - start_cycles;
        
        if (elapsed_time < result.min_time) result.min_time = elapsed_time;
        if (elapsed_time > result.max_time) result.max_time = elapsed_time;
        if (elapsed_cycles < result.min_cycles) result.min_cycles = elapsed_cycles;
        if (elapsed_cycles > result.max_cycles) result.max_cycles = elapsed_cycles;
        
        total_time += elapsed_time;
        total_cycles += elapsed_cycles;
    }
    
    result.avg_time = total_time / config->iterations;
    result.avg_cycles = total_cycles / config->iterations;
    result.throughput_mbps = (data_size / (1024.0 * 1024.0)) / result.min_time;
    result.cycles_per_byte = (double)result.min_cycles / data_size;
    
    free(plaintext);
    free(ciphertext);
    return result;
}

/* Benchmark AVX2 implementation */
static benchmark_result_t benchmark_avx2_encrypt(const benchmark_config_t* config) {
    benchmark_result_t result = {0};
    
    if (!charybdis_avx2_available()) {
        printf("AVX2 not available on this system\n");
        return result;
    }
    
    const size_t data_size = config->nblocks * CHARYBDIS_BLOCK_SIZE;
    
    /* Allocate aligned buffers */
#ifdef _WIN32
    uint8_t* plaintext = (uint8_t*)_aligned_malloc(data_size, 32);
    uint8_t* ciphertext = (uint8_t*)_aligned_malloc(data_size, 32);
#else
    uint8_t* plaintext = (uint8_t*)aligned_alloc(32, data_size);
    uint8_t* ciphertext = (uint8_t*)aligned_alloc(32, data_size);
#endif
    
    uint8_t key[CHARYBDIS_KEY_SIZE];
    uint32_t subkeys[CHARYBDIS_SUBKEYS][4][4];
    charybdis_avx2_context_t avx2_ctx;
    
    if (!plaintext || !ciphertext) {
        printf("Aligned memory allocation failed\n");
#ifdef _WIN32
        _aligned_free(plaintext);
        _aligned_free(ciphertext);
#else
        free(plaintext);
        free(ciphertext);
#endif
        return result;
    }
    
    /* Generate random test data */
    generate_random_data(key, CHARYBDIS_KEY_SIZE);
    generate_random_data(plaintext, data_size);
    
    /* Setup contexts */
    Charybdis_KeySchedule(key, subkeys);
    charybdis_avx2_init_context(&avx2_ctx, subkeys);
    
    /* Warmup */
    for (int i = 0; i < config->warmup_iterations; i++) {
        charybdis_avx2_encrypt_blocks(plaintext, ciphertext, config->nblocks, &avx2_ctx);
    }
    
    /* Benchmark */
    result.min_time = 1e9;
    result.max_time = 0;
    result.min_cycles = UINT64_MAX;
    result.max_cycles = 0;
    double total_time = 0;
    uint64_t total_cycles = 0;
    
    for (int i = 0; i < config->iterations; i++) {
        uint64_t start_cycles = rdtsc();
        double start_time = get_time_seconds();
        
        charybdis_avx2_encrypt_blocks(plaintext, ciphertext, config->nblocks, &avx2_ctx);
        
        double end_time = get_time_seconds();
        uint64_t end_cycles = rdtsc();
        
        double elapsed_time = end_time - start_time;
        uint64_t elapsed_cycles = end_cycles - start_cycles;
        
        if (elapsed_time < result.min_time) result.min_time = elapsed_time;
        if (elapsed_time > result.max_time) result.max_time = elapsed_time;
        if (elapsed_cycles < result.min_cycles) result.min_cycles = elapsed_cycles;
        if (elapsed_cycles > result.max_cycles) result.max_cycles = elapsed_cycles;
        
        total_time += elapsed_time;
        total_cycles += elapsed_cycles;
    }
    
    result.avg_time = total_time / config->iterations;
    result.avg_cycles = total_cycles / config->iterations;
    result.throughput_mbps = (data_size / (1024.0 * 1024.0)) / result.min_time;
    result.cycles_per_byte = (double)result.min_cycles / data_size;
    
    charybdis_avx2_clear_context(&avx2_ctx);
    
#ifdef _WIN32
    _aligned_free(plaintext);
    _aligned_free(ciphertext);
#else
    free(plaintext);
    free(ciphertext);
#endif
    
    return result;
}

/* Print benchmark results */
static void print_benchmark_results(const char* name, const benchmark_result_t* result, double cpu_freq_ghz) {
    printf("=== %s Performance ===\n", name);
    printf("Time (min/avg/max):     %.3f / %.3f / %.3f ms\n",
           result->min_time * 1000, result->avg_time * 1000, result->max_time * 1000);
    printf("Cycles (min/avg/max):   %llu / %llu / %llu\n",
           (unsigned long long)result->min_cycles,
           (unsigned long long)result->avg_cycles,
           (unsigned long long)result->max_cycles);
    printf("Throughput:             %.2f MB/s\n", result->throughput_mbps);
    printf("Cycles per byte:        %.2f\n", result->cycles_per_byte);
    printf("CPU frequency:          %.2f GHz\n", cpu_freq_ghz);
    printf("\n");
}

/* Main benchmark function */
static void run_benchmark(void) {
    printf("=== Charybdis Cipher Performance Benchmark ===\n\n");
    
    /* Estimate CPU frequency */
    printf("Estimating CPU frequency...\n");
    double cpu_freq = estimate_cpu_frequency();
    double cpu_freq_ghz = cpu_freq / 1e9;
    printf("Estimated CPU frequency: %.2f GHz\n\n", cpu_freq_ghz);
    
    /* Benchmark configurations */
    const size_t test_sizes[] = {1, 16, 64, 256, 1024, 4096, 65536};
    const size_t num_test_sizes = sizeof(test_sizes) / sizeof(test_sizes[0]);
    
    benchmark_config_t config = {
        .nblocks = 0,
        .iterations = 100,
        .warmup_iterations = 10,
        .cpu_freq_ghz = cpu_freq_ghz
    };
    
    printf("Benchmark parameters:\n");
    printf("- Iterations: %d\n", config.iterations);
    printf("- Warmup iterations: %d\n", config.warmup_iterations);
    printf("- Block size: %d bytes\n\n", CHARYBDIS_BLOCK_SIZE);
    
    for (size_t i = 0; i < num_test_sizes; i++) {
        config.nblocks = test_sizes[i];
        size_t data_size_kb = (config.nblocks * CHARYBDIS_BLOCK_SIZE) / 1024;
        
        printf("=== Testing with %zu blocks (%zu KB) ===\n", config.nblocks, data_size_kb);
        
        /* Benchmark reference implementation */
        printf("Benchmarking reference implementation...\n");
        benchmark_result_t ref_result = benchmark_reference_encrypt(&config);
        print_benchmark_results("Reference Encryption", &ref_result, cpu_freq_ghz);
        
        /* Benchmark AVX2 implementation */
        if (charybdis_avx2_available()) {
            printf("Benchmarking AVX2 implementation...\n");
            benchmark_result_t avx2_result = benchmark_avx2_encrypt(&config);
            print_benchmark_results("AVX2 Encryption", &avx2_result, cpu_freq_ghz);
            
            /* Calculate speedup */
            if (ref_result.min_time > 0 && avx2_result.min_time > 0) {
                double speedup = ref_result.min_time / avx2_result.min_time;
                printf("=== Performance Comparison ===\n");
                printf("AVX2 speedup:           %.2fx\n", speedup);
                printf("Efficiency gain:        %.1f%%\n", (speedup - 1.0) * 100);
                printf("\n");
            }
        } else {
            printf("AVX2 not available - skipping AVX2 benchmark\n\n");
        }
        
        printf("----------------------------------------\n\n");
    }
    
    printf("Benchmark completed successfully.\n");
}

int main(void) {
    /* Run self-tests first */
    const uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
    };
    const uint8_t pt[64] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
    };
    static const uint8_t expected_ct[64] = {
        0xCF, 0x66, 0x9F, 0xE8, 0x81, 0xE4, 0xE2, 0x44,
        0xA4, 0x83, 0xB7, 0xE4, 0x3F, 0xEF, 0xB0, 0x61,
        0x6A, 0x21, 0x17, 0xAB, 0x7D, 0x1C, 0x3C, 0xCB,
        0xB9, 0x0D, 0x1A, 0xFB, 0xF8, 0x75, 0x45, 0xAD,
        0x84, 0xD7, 0x71, 0x52, 0xDB, 0xBC, 0x37, 0x89,
        0x04, 0xFA, 0x15, 0x25, 0x06, 0x4F, 0xE7, 0xC1,
        0xC2, 0x2C, 0xC9, 0x3C, 0x47, 0x7C, 0x9B, 0x2E,
        0xB8, 0x0F, 0x38, 0x2C, 0x40, 0xB3, 0x21, 0x1B
    };
    uint32_t subkeys[24][4][4];
    uint8_t ct[64], pt_out[64];
	charybdis_avx2_context_t ctx;
    
    // Print test vectors
    printf("=== Charybdis Test Vectors ===\n\n");
    
    // Print key
    printf("Key (M):\n");
    for (int i = 0; i < 32; i++) {
        printf("%02X", key[i]);
    }
    printf("\n\n");
    
    // Print plaintext
    printf("Plaintext (P):\n");
    for (int i = 0; i < 64; i++) {
        printf("%02X", pt[i]);
    }
    printf("\n\n");
    
    // Generate subkeys and print K[1]
    Charybdis_KeySchedule(key, subkeys);
    printf("Subkey K[1]:\n");
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%08X", subkeys[1][i][j]);
        }
    }
    printf("\n\n");
    
    // Encrypt and capture state after round 1
    uint32_t S[4][4];
    // Initial whitening
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            S[i][j] = load_be32(pt + 4 * (4 * i + j)) ^ subkeys[0][i][j];
        }
    }
    // Apply round 1
    Round(S, subkeys[1], 1);
    
    // Print state after round 1
    printf("State S after Round 1:\n");
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%08X", S[i][j]);
        }
    }
    printf("\n\n");
    
    // Complete encryption
    Charybdis_EncryptBlock(pt, ct, subkeys);
    
    // Print ciphertext
    printf("Ciphertext (C):\n");
    for (int i = 0; i < 64; i++) {
        printf("%02X", ct[i]);
    }
    printf("\n\n");
    
    // Verify encryption
    if (memcmp(ct, expected_ct, 64) != 0) {
        printf("Encryption test failed\n");
        return 1;
    }
    
    // Verify decryption
    Charybdis_DecryptBlock(ct, pt_out, subkeys);
    if (memcmp(pt_out, pt, 64) != 0) {
        printf("Decryption test failed\n");
        return 2;
    }
    printf("Charybdis self-test passed\n");

    /* Test AVX2 if available */
    if (charybdis_avx2_available()) {
        if (charybdis_avx2_init_context(&ctx, subkeys) == 0) {
            charybdis_avx2_encrypt_blocks(pt, ct, 1, &ctx);
            if (memcmp(ct, expected_ct, 64) != 0) {
                printf("AVX2 encryption test failed\n");
                return 3;
            }
            charybdis_avx2_decrypt_blocks(ct, pt_out, 1, &ctx);
            if (memcmp(pt_out, pt, 64) != 0) {
                printf("AVX2 decryption test failed\n");
                return 4;
            }
            printf("Charybdis AVX2 self-test passed\n");
            charybdis_avx2_clear_context(&ctx);
        }
    }
    
    /* Run benchmarks */
    run_benchmark();
    return 0;
}
#endif /* BENCHMARK */
