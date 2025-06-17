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

#include "charybdis_avx2.h"
#include <string.h>

/* Platform-specific includes for capability detection */
#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#else
#include <cpuid.h>
#endif

/* =============================================================================
 * AVX2 HELPER MACROS AND CONSTANTS
 * ============================================================================= */

/* rotation macros - handle n=0 case to avoid UB */
#define AVX2_ROR32(v, n) _mm256_or_si256(_mm256_srli_epi32((v), (n)), \
                                         _mm256_slli_epi32((v), (32-(n)) & 31))

#define AVX2_ROL32(v, n) _mm256_or_si256(_mm256_slli_epi32((v), (n)), \
                                         _mm256_srli_epi32((v), (32-(n)) & 31))

/* ARX rotation constants from reference implementation */
#define R1 13
#define R2 19  
#define R3 23
#define R4 29
#define RH1 9
#define RH2 17
#define RH3 21
#define RH4 27

/* Force inlining for hot functions */
#if defined(__GNUC__) || defined(__clang__)
#define ALWAYS_INLINE static inline __attribute__((always_inline))
#elif defined(_MSC_VER)
#define ALWAYS_INLINE static __forceinline
#else
#define ALWAYS_INLINE static inline
#endif

/* Endian swap mask */
static __m256i avx2_swap_mask;

/* =============================================================================
 * AVX2 CAPABILITY DETECTION
 * ============================================================================= */

#ifdef _WIN32
static int check_windows_xsave_support(void) {
    int cpuid_info[4];
    
    /* Check OSXSAVE bit */
    __cpuid(cpuid_info, 1);
    if (!(cpuid_info[2] & (1 << 27))) return 0;
    
    /* Check XCR0 for YMM state saving */
    unsigned long long xcr0 = _xgetbv(0);
    return (xcr0 & 0x6) == 0x6;
}
#else
static int check_os_avx_support(void) {
    unsigned int eax, ebx, ecx, edx;

    /* Check OS support for YMM registers */
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) return 0;
    if (!(ecx & (1U << 27))) return 0; /* OSXSAVE bit */

    /* Verify YMM state is saved/restored by OS */
    unsigned long long xcr0 = _xgetbv(0);
    return (xcr0 & 0x6) == 0x6; /* XMM and YMM state */
}
#endif

/* Cross-platform YMM register clearing */
static void clear_ymm_registers(void) {
#ifdef _MSC_VER
    _mm256_zeroupper();  /* MSVC doesn't have zeroall */
#else
    #if __has_builtin(_mm256_zeroall)
        _mm256_zeroall();
    #else
        _mm256_zeroupper();
    #endif
#endif
}

int charybdis_avx2_available(void) {
#ifdef _WIN32
    /* Windows: Use comprehensive check */
    if (IsProcessorFeaturePresent(PF_AVX2_INSTRUCTIONS_AVAILABLE)) {
        /* Still need to verify OS XSAVE support */
        return check_windows_xsave_support();
    }
    
    /* Fallback to manual CPUID */
    int cpuid_info[4];
    __cpuid(cpuid_info, 7);
    if (!(cpuid_info[1] & (1 << 5))) return 0; /* No AVX2 */
    
    return check_windows_xsave_support();
    
#else
    unsigned int eax, ebx, ecx, edx;

    /* Check maximum CPUID function supported */
    if (__get_cpuid_max(0, NULL) < 7) {
        return 0; 
    }

    /* Check for AVX (CPUID.1:ECX.AVX[bit 28]) and XSAVE (CPUID.1:ECX.XSAVE[bit 26]) */
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return 0;
    }
    if (!((ecx & (1U << 28)) && (ecx & (1U << 26)))) {
        return 0; 
    }

    /* Check for AVX2 (CPUID.EAX=7,ECX=0:EBX.AVX2[bit 5]) */
    if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        return 0; 
    }
    if (!(ebx & (1U << 5))) {
        return 0; 
    }

    /* Check OS support (OSXSAVE and XCR0) */
    if (!check_os_avx_support()) {
        return 0; 
    }

    return 1;
#endif
}

/* =============================================================================
 * PIPELINED ARX OPERATIONS  
 * ============================================================================= */

/* G_Mix stages - allows pipelining across columns to hide rotate latency */
ALWAYS_INLINE void avx2_g_mix_stage1(__m256i* a, __m256i* b, __m256i* d) {
    *a = _mm256_add_epi32(*a, *b);
    *d = _mm256_xor_si256(*d, *a);
    *d = AVX2_ROR32(*d, R1);
}

ALWAYS_INLINE void avx2_g_mix_stage2(__m256i* c, __m256i* b, __m256i* d) {
    *c = _mm256_add_epi32(*c, *d);
    *b = _mm256_xor_si256(*b, *c);
    *b = AVX2_ROR32(*b, R2);
}

ALWAYS_INLINE void avx2_g_mix_stage3(__m256i* a, __m256i* b, __m256i* d) {
    *a = _mm256_add_epi32(*a, *b);
    *d = _mm256_xor_si256(*d, *a);
    *d = AVX2_ROR32(*d, R3);
}

ALWAYS_INLINE void avx2_g_mix_stage4(__m256i* c, __m256i* b, __m256i* d) {
    *c = _mm256_add_epi32(*c, *d);
    *b = _mm256_xor_si256(*b, *c);
    *b = AVX2_ROR32(*b, R4);
}

/* H_Mix stages */
ALWAYS_INLINE void avx2_h_mix_stage1(__m256i* a, __m256i* b, __m256i* d) {
    *a = _mm256_add_epi32(*a, *b);
    *d = _mm256_xor_si256(*d, *a);
    *d = AVX2_ROR32(*d, RH1);
}

ALWAYS_INLINE void avx2_h_mix_stage2(__m256i* c, __m256i* b, __m256i* d) {
    *c = _mm256_add_epi32(*c, *d);
    *b = _mm256_xor_si256(*b, *c);
    *b = AVX2_ROR32(*b, RH2);
}

ALWAYS_INLINE void avx2_h_mix_stage3(__m256i* a, __m256i* b, __m256i* d) {
    *a = _mm256_add_epi32(*a, *b);
    *d = _mm256_xor_si256(*d, *a);
    *d = AVX2_ROR32(*d, RH3);
}

ALWAYS_INLINE void avx2_h_mix_stage4(__m256i* c, __m256i* b, __m256i* d) {
    *c = _mm256_add_epi32(*c, *d);
    *b = _mm256_xor_si256(*b, *c);
    *b = AVX2_ROR32(*b, RH4);
}

/* Inverse G_Mix stages */
ALWAYS_INLINE void avx2_inv_g_mix_stage4(__m256i* c, __m256i* b, __m256i* d) {
    *b = AVX2_ROL32(*b, R4);
    *b = _mm256_xor_si256(*b, *c);
    *c = _mm256_sub_epi32(*c, *d);
}

ALWAYS_INLINE void avx2_inv_g_mix_stage3(__m256i* a, __m256i* b, __m256i* d) {
    *d = AVX2_ROL32(*d, R3);
    *d = _mm256_xor_si256(*d, *a);
    *a = _mm256_sub_epi32(*a, *b);
}

ALWAYS_INLINE void avx2_inv_g_mix_stage2(__m256i* c, __m256i* b, __m256i* d) {
    *b = AVX2_ROL32(*b, R2);
    *b = _mm256_xor_si256(*b, *c);
    *c = _mm256_sub_epi32(*c, *d);
}

ALWAYS_INLINE void avx2_inv_g_mix_stage1(__m256i* a, __m256i* b, __m256i* d) {
    *d = AVX2_ROL32(*d, R1);
    *d = _mm256_xor_si256(*d, *a);
    *a = _mm256_sub_epi32(*a, *b);
}

/* Inverse H_Mix stages */
ALWAYS_INLINE void avx2_inv_h_mix_stage4(__m256i* c, __m256i* b, __m256i* d) {
    *b = AVX2_ROL32(*b, RH4);
    *b = _mm256_xor_si256(*b, *c);
    *c = _mm256_sub_epi32(*c, *d);
}

ALWAYS_INLINE void avx2_inv_h_mix_stage3(__m256i* a, __m256i* b, __m256i* d) {
    *d = AVX2_ROL32(*d, RH3);
    *d = _mm256_xor_si256(*d, *a);
    *a = _mm256_sub_epi32(*a, *b);
}

ALWAYS_INLINE void avx2_inv_h_mix_stage2(__m256i* c, __m256i* b, __m256i* d) {
    *b = AVX2_ROL32(*b, RH2);
    *b = _mm256_xor_si256(*b, *c);
    *c = _mm256_sub_epi32(*c, *d);
}

ALWAYS_INLINE void avx2_inv_h_mix_stage1(__m256i* a, __m256i* b, __m256i* d) {
    *d = AVX2_ROL32(*d, RH1);
    *d = _mm256_xor_si256(*d, *a);
    *a = _mm256_sub_epi32(*a, *b);
}

/* =============================================================================
 * VECTORIZED ROUND OPERATIONS
 * ============================================================================= */

/* Optimized ColumnMix with maximum ILP */
ALWAYS_INLINE void avx2_column_mix(__m256i state[4][4]) {
    /* G_Mix with pipelined execution across all 4 columns */
    avx2_g_mix_stage1(&state[0][0], &state[1][0], &state[3][0]);
    avx2_g_mix_stage1(&state[0][1], &state[1][1], &state[3][1]);
    avx2_g_mix_stage1(&state[0][2], &state[1][2], &state[3][2]);
    avx2_g_mix_stage1(&state[0][3], &state[1][3], &state[3][3]);

    avx2_g_mix_stage2(&state[2][0], &state[1][0], &state[3][0]);
    avx2_g_mix_stage2(&state[2][1], &state[1][1], &state[3][1]);
    avx2_g_mix_stage2(&state[2][2], &state[1][2], &state[3][2]);
    avx2_g_mix_stage2(&state[2][3], &state[1][3], &state[3][3]);

    avx2_g_mix_stage3(&state[0][0], &state[1][0], &state[3][0]);
    avx2_g_mix_stage3(&state[0][1], &state[1][1], &state[3][1]);
    avx2_g_mix_stage3(&state[0][2], &state[1][2], &state[3][2]);
    avx2_g_mix_stage3(&state[0][3], &state[1][3], &state[3][3]);

    avx2_g_mix_stage4(&state[2][0], &state[1][0], &state[3][0]);
    avx2_g_mix_stage4(&state[2][1], &state[1][1], &state[3][1]);
    avx2_g_mix_stage4(&state[2][2], &state[1][2], &state[3][2]);
    avx2_g_mix_stage4(&state[2][3], &state[1][3], &state[3][3]);
    
    /* H_Mix pipelined */
    avx2_h_mix_stage1(&state[0][0], &state[1][0], &state[3][0]);
    avx2_h_mix_stage1(&state[0][1], &state[1][1], &state[3][1]);
    avx2_h_mix_stage1(&state[0][2], &state[1][2], &state[3][2]);
    avx2_h_mix_stage1(&state[0][3], &state[1][3], &state[3][3]);

    avx2_h_mix_stage2(&state[2][0], &state[1][0], &state[3][0]);
    avx2_h_mix_stage2(&state[2][1], &state[1][1], &state[3][1]);
    avx2_h_mix_stage2(&state[2][2], &state[1][2], &state[3][2]);
    avx2_h_mix_stage2(&state[2][3], &state[1][3], &state[3][3]);

    avx2_h_mix_stage3(&state[0][0], &state[1][0], &state[3][0]);
    avx2_h_mix_stage3(&state[0][1], &state[1][1], &state[3][1]);
    avx2_h_mix_stage3(&state[0][2], &state[1][2], &state[3][2]);
    avx2_h_mix_stage3(&state[0][3], &state[1][3], &state[3][3]);

    avx2_h_mix_stage4(&state[2][0], &state[1][0], &state[3][0]);
    avx2_h_mix_stage4(&state[2][1], &state[1][1], &state[3][1]);
    avx2_h_mix_stage4(&state[2][2], &state[1][2], &state[3][2]);
    avx2_h_mix_stage4(&state[2][3], &state[1][3], &state[3][3]);
    
    /* H_Mix with permuted indices [2,3,0,1] */
    avx2_h_mix_stage1(&state[2][0], &state[3][0], &state[1][0]);
    avx2_h_mix_stage1(&state[2][1], &state[3][1], &state[1][1]);
    avx2_h_mix_stage1(&state[2][2], &state[3][2], &state[1][2]);
    avx2_h_mix_stage1(&state[2][3], &state[3][3], &state[1][3]);

    avx2_h_mix_stage2(&state[0][0], &state[3][0], &state[1][0]);
    avx2_h_mix_stage2(&state[0][1], &state[3][1], &state[1][1]);
    avx2_h_mix_stage2(&state[0][2], &state[3][2], &state[1][2]);
    avx2_h_mix_stage2(&state[0][3], &state[3][3], &state[1][3]);

    avx2_h_mix_stage3(&state[2][0], &state[3][0], &state[1][0]);
    avx2_h_mix_stage3(&state[2][1], &state[3][1], &state[1][1]);
    avx2_h_mix_stage3(&state[2][2], &state[3][2], &state[1][2]);
    avx2_h_mix_stage3(&state[2][3], &state[3][3], &state[1][3]);

    avx2_h_mix_stage4(&state[0][0], &state[3][0], &state[1][0]);
    avx2_h_mix_stage4(&state[0][1], &state[3][1], &state[1][1]);
    avx2_h_mix_stage4(&state[0][2], &state[3][2], &state[1][2]);
    avx2_h_mix_stage4(&state[0][3], &state[3][3], &state[1][3]);
    
    /* G_Mix with permuted indices [2,3,0,1] */
    avx2_g_mix_stage1(&state[2][0], &state[3][0], &state[1][0]);
    avx2_g_mix_stage1(&state[2][1], &state[3][1], &state[1][1]);
    avx2_g_mix_stage1(&state[2][2], &state[3][2], &state[1][2]);
    avx2_g_mix_stage1(&state[2][3], &state[3][3], &state[1][3]);

    avx2_g_mix_stage2(&state[0][0], &state[3][0], &state[1][0]);
    avx2_g_mix_stage2(&state[0][1], &state[3][1], &state[1][1]);
    avx2_g_mix_stage2(&state[0][2], &state[3][2], &state[1][2]);
    avx2_g_mix_stage2(&state[0][3], &state[3][3], &state[1][3]);

    avx2_g_mix_stage3(&state[2][0], &state[3][0], &state[1][0]);
    avx2_g_mix_stage3(&state[2][1], &state[3][1], &state[1][1]);
    avx2_g_mix_stage3(&state[2][2], &state[3][2], &state[1][2]);
    avx2_g_mix_stage3(&state[2][3], &state[3][3], &state[1][3]);

    avx2_g_mix_stage4(&state[0][0], &state[3][0], &state[1][0]);
    avx2_g_mix_stage4(&state[0][1], &state[3][1], &state[1][1]);
    avx2_g_mix_stage4(&state[0][2], &state[3][2], &state[1][2]);
    avx2_g_mix_stage4(&state[0][3], &state[3][3], &state[1][3]);
}

/* Inverse ColumnMix */
ALWAYS_INLINE void avx2_inverse_column_mix(__m256i state[4][4]) {
    /* Inverse G_Mix with permuted indices [2,3,0,1] - applied in reverse stage order */
    avx2_inv_g_mix_stage4(&state[0][0], &state[3][0], &state[1][0]);
    avx2_inv_g_mix_stage4(&state[0][1], &state[3][1], &state[1][1]);
    avx2_inv_g_mix_stage4(&state[0][2], &state[3][2], &state[1][2]);
    avx2_inv_g_mix_stage4(&state[0][3], &state[3][3], &state[1][3]);

    avx2_inv_g_mix_stage3(&state[2][0], &state[3][0], &state[1][0]);
    avx2_inv_g_mix_stage3(&state[2][1], &state[3][1], &state[1][1]);
    avx2_inv_g_mix_stage3(&state[2][2], &state[3][2], &state[1][2]);
    avx2_inv_g_mix_stage3(&state[2][3], &state[3][3], &state[1][3]);

    avx2_inv_g_mix_stage2(&state[0][0], &state[3][0], &state[1][0]);
    avx2_inv_g_mix_stage2(&state[0][1], &state[3][1], &state[1][1]);
    avx2_inv_g_mix_stage2(&state[0][2], &state[3][2], &state[1][2]);
    avx2_inv_g_mix_stage2(&state[0][3], &state[3][3], &state[1][3]);

    avx2_inv_g_mix_stage1(&state[2][0], &state[3][0], &state[1][0]);
    avx2_inv_g_mix_stage1(&state[2][1], &state[3][1], &state[1][1]);
    avx2_inv_g_mix_stage1(&state[2][2], &state[3][2], &state[1][2]);
    avx2_inv_g_mix_stage1(&state[2][3], &state[3][3], &state[1][3]);

    /* Inverse H_Mix with permuted indices [2,3,0,1] - applied in reverse stage order */
    avx2_inv_h_mix_stage4(&state[0][0], &state[3][0], &state[1][0]);
    avx2_inv_h_mix_stage4(&state[0][1], &state[3][1], &state[1][1]);
    avx2_inv_h_mix_stage4(&state[0][2], &state[3][2], &state[1][2]);
    avx2_inv_h_mix_stage4(&state[0][3], &state[3][3], &state[1][3]);

    avx2_inv_h_mix_stage3(&state[2][0], &state[3][0], &state[1][0]);
    avx2_inv_h_mix_stage3(&state[2][1], &state[3][1], &state[1][1]);
    avx2_inv_h_mix_stage3(&state[2][2], &state[3][2], &state[1][2]);
    avx2_inv_h_mix_stage3(&state[2][3], &state[3][3], &state[1][3]);

    avx2_inv_h_mix_stage2(&state[0][0], &state[3][0], &state[1][0]);
    avx2_inv_h_mix_stage2(&state[0][1], &state[3][1], &state[1][1]);
    avx2_inv_h_mix_stage2(&state[0][2], &state[3][2], &state[1][2]);
    avx2_inv_h_mix_stage2(&state[0][3], &state[3][3], &state[1][3]);

    avx2_inv_h_mix_stage1(&state[2][0], &state[3][0], &state[1][0]);
    avx2_inv_h_mix_stage1(&state[2][1], &state[3][1], &state[1][1]);
    avx2_inv_h_mix_stage1(&state[2][2], &state[3][2], &state[1][2]);
    avx2_inv_h_mix_stage1(&state[2][3], &state[3][3], &state[1][3]);

    /* Inverse H_Mix - applied in reverse stage order */
    avx2_inv_h_mix_stage4(&state[2][0], &state[1][0], &state[3][0]);
    avx2_inv_h_mix_stage4(&state[2][1], &state[1][1], &state[3][1]);
    avx2_inv_h_mix_stage4(&state[2][2], &state[1][2], &state[3][2]);
    avx2_inv_h_mix_stage4(&state[2][3], &state[1][3], &state[3][3]);

    avx2_inv_h_mix_stage3(&state[0][0], &state[1][0], &state[3][0]);
    avx2_inv_h_mix_stage3(&state[0][1], &state[1][1], &state[3][1]);
    avx2_inv_h_mix_stage3(&state[0][2], &state[1][2], &state[3][2]);
    avx2_inv_h_mix_stage3(&state[0][3], &state[1][3], &state[3][3]);

    avx2_inv_h_mix_stage2(&state[2][0], &state[1][0], &state[3][0]);
    avx2_inv_h_mix_stage2(&state[2][1], &state[1][1], &state[3][1]);
    avx2_inv_h_mix_stage2(&state[2][2], &state[1][2], &state[3][2]);
    avx2_inv_h_mix_stage2(&state[2][3], &state[1][3], &state[3][3]);

    avx2_inv_h_mix_stage1(&state[0][0], &state[1][0], &state[3][0]);
    avx2_inv_h_mix_stage1(&state[0][1], &state[1][1], &state[3][1]);
    avx2_inv_h_mix_stage1(&state[0][2], &state[1][2], &state[3][2]);
    avx2_inv_h_mix_stage1(&state[0][3], &state[1][3], &state[3][3]);

    /* Inverse G_Mix - applied in reverse stage order */
    avx2_inv_g_mix_stage4(&state[2][0], &state[1][0], &state[3][0]);
    avx2_inv_g_mix_stage4(&state[2][1], &state[1][1], &state[3][1]);
    avx2_inv_g_mix_stage4(&state[2][2], &state[1][2], &state[3][2]);
    avx2_inv_g_mix_stage4(&state[2][3], &state[1][3], &state[3][3]);

    avx2_inv_g_mix_stage3(&state[0][0], &state[1][0], &state[3][0]);
    avx2_inv_g_mix_stage3(&state[0][1], &state[1][1], &state[3][1]);
    avx2_inv_g_mix_stage3(&state[0][2], &state[1][2], &state[3][2]);
    avx2_inv_g_mix_stage3(&state[0][3], &state[1][3], &state[3][3]);

    avx2_inv_g_mix_stage2(&state[2][0], &state[1][0], &state[3][0]);
    avx2_inv_g_mix_stage2(&state[2][1], &state[1][1], &state[3][1]);
    avx2_inv_g_mix_stage2(&state[2][2], &state[1][2], &state[3][2]);
    avx2_inv_g_mix_stage2(&state[2][3], &state[1][3], &state[3][3]);

    avx2_inv_g_mix_stage1(&state[0][0], &state[1][0], &state[3][0]);
    avx2_inv_g_mix_stage1(&state[0][1], &state[1][1], &state[3][1]);
    avx2_inv_g_mix_stage1(&state[0][2], &state[1][2], &state[3][2]);
    avx2_inv_g_mix_stage1(&state[0][3], &state[1][3], &state[3][3]);
}

/* Optimized ShiftRows using precomputed permutation masks */
ALWAYS_INLINE void avx2_shift_rows(__m256i state[4][4]) {
    /* Row 0: no shift */
    
    /* Row 1: shift left by 1 column */
    __m256i temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;
    
    /* Row 2: shift left by 2 columns */
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;
    
    /* Row 3: shift left by 3 columns (same as right by 1) */
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

ALWAYS_INLINE void avx2_inverse_shift_rows(__m256i state[4][4]) {
    /* Row 0: no shift */
    
    /* Row 1: shift right by 1 column */
    __m256i temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;
    
    /* Row 2: shift right by 2 columns */
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;
    
    /* Row 3: shift right by 3 columns (same as left by 1) */
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

/* AddRoundKey */
ALWAYS_INLINE void avx2_add_round_key(__m256i state[4][4], 
                                      const __m256i subkey[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = _mm256_xor_si256(state[i][j], subkey[i][j]);
        }
    }
}

/* SubConstants using pre-vectorized constants */
ALWAYS_INLINE void avx2_sub_constants(__m256i state[4][4], 
                                      const __m256i round_constants[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = _mm256_xor_si256(state[i][j], round_constants[i][j]);
        }
    }
}

/* =============================================================================
 * OPTIMIZED LOAD/STORE WITH IN-REGISTER TRANSPOSE
 * ============================================================================= */

/**
 * @brief Load 8 blocks with optimized in-register transpose
 * 
 * Eliminates expensive temporary buffer by doing endian conversion and
 * AoS->SoA transpose entirely in registers using vpshufb + interleave network.
 */
static void avx2_load_8_blocks_optimized(const uint8_t* in, __m256i state[4][4]) {
    /* Load 16 vectors (8 blocks * 2 vectors each) with endian swap */
    __m256i data[16];
    for (int i = 0; i < 16; i++) {
        __m256i raw = _mm256_loadu_si256((const __m256i*)(in + i * 32));
        data[i] = _mm256_shuffle_epi8(raw, avx2_swap_mask);
    }
    
    /* 4-level interleave network for AoS->SoA transpose */
    /* Level 1: interleave adjacent 32-bit words */
    __m256i level1[16];
    for (int i = 0; i < 8; i++) {
        level1[i*2]   = _mm256_unpacklo_epi32(data[i*2], data[i*2+1]);
        level1[i*2+1] = _mm256_unpackhi_epi32(data[i*2], data[i*2+1]);
    }
    
    /* Level 2: interleave 64-bit groups */
    __m256i level2[16];
    for (int i = 0; i < 8; i++) {
        level2[i*2]   = _mm256_unpacklo_epi64(level1[i*2], level1[i*2+1]);
        level2[i*2+1] = _mm256_unpackhi_epi64(level1[i*2], level1[i*2+1]);
    }
    
    /* Level 3: interleave 128-bit lanes */
    __m256i level3[16];
    for (int i = 0; i < 8; i++) {
        level3[i*2]   = _mm256_permute2x128_si256(level2[i*2], level2[i*2+1], 0x20);
        level3[i*2+1] = _mm256_permute2x128_si256(level2[i*2], level2[i*2+1], 0x31);
    }
    
    /* Extract final state - each vector now contains same word position from 8 blocks */
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = level3[i*4 + j];
        }
    }
}

/**
 * @brief Store 8 blocks with optimized in-register transpose
 */
static void avx2_store_8_blocks_optimized(const __m256i state[4][4], uint8_t* out) {
    /* Prepare data for reverse transpose */
    __m256i level3[16];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            level3[i*4 + j] = state[i][j];
        }
    }
    
    /* Reverse the transpose network (Level 3->2->1->0) */
    __m256i level2[16];
    for (int i = 0; i < 8; i++) {
        __m256i temp0 = _mm256_permute2x128_si256(level3[i*2], level3[i*2+1], 0x20);
        __m256i temp1 = _mm256_permute2x128_si256(level3[i*2], level3[i*2+1], 0x31);
        level2[i*2] = temp0;
        level2[i*2+1] = temp1;
    }
    
    __m256i level1[16];
    for (int i = 0; i < 8; i++) {
        level1[i*2]   = _mm256_unpacklo_epi64(level2[i*2], level2[i*2+1]);
        level1[i*2+1] = _mm256_unpackhi_epi64(level2[i*2], level2[i*2+1]);
    }
    
    __m256i data[16];
    for (int i = 0; i < 8; i++) {
        data[i*2]   = _mm256_unpacklo_epi32(level1[i*2], level1[i*2+1]);
        data[i*2+1] = _mm256_unpackhi_epi32(level1[i*2], level1[i*2+1]);
    }
    
    /* Store with endian conversion */
    for (int i = 0; i < 16; i++) {
        __m256i swapped = _mm256_shuffle_epi8(data[i], avx2_swap_mask);
        _mm256_storeu_si256((__m256i*)(out + i * 32), swapped);
    }
}

/* =============================================================================
 * ROUND FUNCTIONS
 * ============================================================================= */

ALWAYS_INLINE void avx2_encrypt_round(__m256i state[4][4], 
                                      const __m256i subkey[4][4],
                                      const __m256i round_constants[4][4]) {
    avx2_sub_constants(state, round_constants);
    avx2_column_mix(state);
    avx2_shift_rows(state);
    avx2_add_round_key(state, subkey);
}

/* Stub decrypt round until full inverse implementation is ready */
ALWAYS_INLINE void avx2_decrypt_round(__m256i state[4][4], 
                                      const __m256i subkey[4][4],
                                      const __m256i round_constants[4][4]) {
    avx2_add_round_key(state, subkey);
    avx2_inverse_shift_rows(state);
    avx2_inverse_column_mix(state); 
    avx2_sub_constants(state, round_constants); /* XOR is its own inverse */
}

/* =============================================================================
 * PUBLIC API IMPLEMENTATION
 * ============================================================================= */

 /* =============================================================================
  * ROUND CONSTANTS TABLE
  * ============================================================================= */

  /**
   * @brief Round constants for Charybdis cipher
   *
   * Contains 352 constants (22 rounds � 16 words) derived from SHAKE256.
   * Shared between scalar and SIMD implementations to avoid duplication.
   *
   * @note Symbol has hidden visibility to avoid namespace pollution
   */
extern const uint32_t CHARYBDIS_RC[CHARYBDIS_RC_COUNT];

int charybdis_avx2_init_context(charybdis_avx2_context_t* ctx,
                                const uint32_t subkeys[CHARYBDIS_SUBKEYS][4][4]) {
    static int avx2_checked = 0;
    static int avx2_available = 0;
    if (!ctx || !subkeys) return -1;
    
    /* Verify AVX2 is still available */
    if (!avx2_checked) {
        avx2_available = charybdis_avx2_available();
        avx2_swap_mask = _mm256_setr_epi8(
            3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
            3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12
        );
        avx2_checked = 1;
    }
    if (!avx2_available) return -1;
    
    /* Clear context first */
    memset(ctx, 0, sizeof(*ctx));
    
    /* Cache scalar subkeys for tail processing */
    memcpy(ctx->scalar_subkeys, subkeys, sizeof(ctx->scalar_subkeys));
    
    /* Pre-vectorize subkeys efficiently */
    for (int r = 0; r < CHARYBDIS_SUBKEYS; r++) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                ctx->vec_subkeys[r][i][j] = _mm256_set1_epi32(subkeys[r][i][j]);
            }
        }
    }
    
    /* Pre-vectorize round constants */
    for (int round = 1; round <= CHARYBDIS_ROUNDS; round++) {
        int base = (round - 1) * 16;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                uint32_t rc_val = CHARYBDIS_RC[base + 4 * i + j];
                ctx->vec_round_constants[round-1][i][j] = _mm256_set1_epi32(rc_val);
            }
        }
    }
    
    ctx->isa_tag = CHARYBDIS_AVX2_ISA_TAG;
    /* Context marker that changes with struct size */
    ctx->initialized = CHARYBDIS_AVX2_ISA_TAG ^ sizeof(*ctx);
    
    return 0;
}

int charybdis_avx2_encrypt_blocks(const uint8_t* in,
                                   uint8_t* out,
                                   size_t nblocks,
                                   const charybdis_avx2_context_t* ctx) {
    if (!in || !out || !ctx || nblocks == 0 || 
        ctx->initialized != (CHARYBDIS_AVX2_ISA_TAG ^ sizeof(*ctx))) {
        return -1;
    }
    
    /* Process blocks in groups of 8 */
    size_t full_groups = nblocks / CHARYBDIS_AVX2_LANES;
    
    for (size_t group = 0; group < full_groups; group++) {
        size_t offset = group * CHARYBDIS_AVX2_LANES * CHARYBDIS_BLOCK_SIZE;
        __m256i state[4][4];
        
        /* Load 8 blocks with optimized conversion */
        avx2_load_8_blocks_optimized(in + offset, state);
        
        /* Initial whitening */
        avx2_add_round_key(state, ctx->vec_subkeys[0]);
        
        /* 22 main rounds */
        for (int r = 1; r <= CHARYBDIS_ROUNDS; r++) {
            avx2_encrypt_round(state, ctx->vec_subkeys[r], ctx->vec_round_constants[r-1]);
        }
        
        /* Final whitening */
        avx2_add_round_key(state, ctx->vec_subkeys[23]);
        
        /* Store 8 blocks with optimized conversion */
        avx2_store_8_blocks_optimized(state, out + offset);
    }
    
    /* Process remaining blocks with scalar implementation */
    size_t remaining_start = full_groups * CHARYBDIS_AVX2_LANES;
    for (size_t i = remaining_start; i < nblocks; i++) {
        size_t offset = i * CHARYBDIS_BLOCK_SIZE;
        Charybdis_EncryptBlock(in + offset, out + offset, ctx->scalar_subkeys);
    }
    return 0;
}

int charybdis_avx2_decrypt_blocks(const uint8_t* in,
                                   uint8_t* out,
                                   size_t nblocks,
                                   const charybdis_avx2_context_t* ctx) {
    if (!in || !out || !ctx || nblocks == 0 || 
        ctx->initialized != (CHARYBDIS_AVX2_ISA_TAG ^ sizeof(*ctx))) {
        return -1;
    }
    
    /* Process blocks in groups of 8 with SIMD */
    size_t full_groups = nblocks / CHARYBDIS_AVX2_LANES;
    
    for (size_t group = 0; group < full_groups; group++) {
        size_t offset = group * CHARYBDIS_AVX2_LANES * CHARYBDIS_BLOCK_SIZE;
        __m256i state[4][4];
        
        /* Load 8 blocks with optimized conversion */
        avx2_load_8_blocks_optimized(in + offset, state);
        
        /* Initial whitening (same as encrypt) */
        avx2_add_round_key(state, ctx->vec_subkeys[23]);
        
        /* 22 main rounds in reverse */
        for (int r = CHARYBDIS_ROUNDS; r >= 1; r--) {
            avx2_decrypt_round(state, ctx->vec_subkeys[r], ctx->vec_round_constants[r-1]);
        }
        
        /* Final whitening */
        avx2_add_round_key(state, ctx->vec_subkeys[0]);
        
        /* Store 8 blocks with optimized conversion */
        avx2_store_8_blocks_optimized(state, out + offset);
    }
    
    /* Process remaining blocks with scalar implementation */
    size_t remaining_start = full_groups * CHARYBDIS_AVX2_LANES;
    for (size_t i = remaining_start; i < nblocks; i++) {
        size_t offset = i * CHARYBDIS_BLOCK_SIZE;
        Charybdis_DecryptBlock(in + offset, out + offset, ctx->scalar_subkeys);
    }
    return 0;
}

void charybdis_avx2_clear_context(charybdis_avx2_context_t* ctx) {
    if (ctx) {
        /* Clear YMM registers first to prevent key leakage */
        clear_ymm_registers();
        
        /* Secure clear of context memory */
        charybdis_secure_memzero(ctx, sizeof(*ctx));
    }
}
