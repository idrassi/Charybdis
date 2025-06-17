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
static const uint32_t KSC[736] = {
    0x22CE1456, 0x855FCC07, 0x38FAC46E, 0x84DB64E7, 0xB56E62D4, 0xFB179D45, 0xA877D120, 0x20DBA111,
    0x52B4EA96, 0x632042F7, 0x717E08F1, 0xEFDF9BE4, 0x08369D2D, 0x3990F255, 0x7E1F99D4, 0x9F366498,
    0x39C3E39F, 0x99420A7D, 0xDC823582, 0x140C77C5, 0x1D0646D9, 0x596006DA, 0xD553C7A5, 0x5201BECC,
    0x86EE9B90, 0x16B533EA, 0x2EF67C09, 0xF0E7174D, 0x10208A50, 0x62203E26, 0xB2A865EA, 0x62D80231,
    0x7806CE61, 0x4A97EC1A, 0x87028442, 0x1B4A6733, 0xF2540FB7, 0x0F9CE941, 0xCE80F760, 0xB65C7F67,
    0x7A1C43D9, 0x071BCFE6, 0x103B7FE6, 0x3287FC5F, 0xF52A4F41, 0x0D98C4A5, 0x9B377109, 0xA16DE3D0,
    0xD3C2D8C2, 0x18ACBB65, 0x4917CC8C, 0x03E00F0F, 0x53C9CD61, 0xA3D7F320, 0x47E672E4, 0x90084B9A,
    0xBB0E27A4, 0x526DAEA1, 0xBB3A051C, 0x58A142FE, 0xD31F84D0, 0xFBE6A228, 0xF1413B72, 0xE375AB21,
    0x1EBF7F5A, 0x968D674B, 0xAD9C1F24, 0x65E5B273, 0x6B2B36B0, 0xAC0A32F8, 0xC06467CB, 0x5859E7FA,
    0x4828422F, 0x4281F376, 0x9DE07037, 0x116FE065, 0x208D31E2, 0x7DA3BAFA, 0xD1FE7944, 0x2D6817C2,
    0xE1853EE2, 0x4CE45237, 0x4B37D13A, 0x1B356A6D, 0xF8DDB2A6, 0x0863569A, 0xF44E3DD2, 0xA7C6778E,
    0xCD0D8CC8, 0x33EA7F1B, 0x2CAD2545, 0x3F3B795B, 0xBAB3DB6C, 0xCE1C939B, 0xDF7BABB1, 0x7A4F4F31,
    0x0ACD88AA, 0x8C9F6FCF, 0x822FE1F6, 0xED0E9EDF, 0x6B39F9CD, 0xA8F14315, 0x7FCE61F5, 0xE6125AF6,
    0x4A0C4640, 0x47B8233B, 0x1E9D0330, 0x5B47A121, 0xDCD443FD, 0x8124A733, 0x9CF7DECE, 0x46C4633A,
    0x5E1118BA, 0x0E9AFA30, 0x80B9700D, 0xB7F66BDF, 0x722FB410, 0x7E6F01FB, 0x2E08D391, 0xDD429EA5,
    0x19FB306E, 0xF1371732, 0x0FE00930, 0xD7A5CE21, 0xD0468078, 0x9AA9F859, 0xDB44C4BA, 0xA5F32457,
    0x71714286, 0x1020C0F7, 0x79B1D11D, 0x5C16FAFE, 0xEB988E90, 0x826E42C4, 0x4CB4E340, 0xCB6D4A43,
    0x4800D3E1, 0xE3760040, 0xCA4B2BA7, 0xF95364A0, 0x7F58C0C8, 0xBA46D6F8, 0x1BB07996, 0xC8CCBA43,
    0x5E632CC9, 0x0497D257, 0xD58FDF2C, 0x1D113729, 0x7CEA7886, 0x14A815EB, 0xA6592A36, 0x619C92F0,
    0x354D9C3C, 0x573E61A4, 0xC236724D, 0xFB6BB3E8, 0x76CD8756, 0xB6F81B16, 0xF81E90EF, 0x3447F438,
    0x6F8A51C8, 0xAD11B6A7, 0xE66669A1, 0x09F1A5E0, 0x5160CC90, 0x6B645070, 0x33CA9D18, 0x1622CC5F,
    0xFFF43803, 0xC915A337, 0x9B159F26, 0xDF448F5B, 0x06221AB0, 0xB5B43610, 0x3DBC8BCE, 0x4D34903D,
    0xE38473AB, 0x1D43A01D, 0xF075D6F4, 0x7CDF0536, 0xBFF72C04, 0x341072BB, 0xA151438B, 0x90FFCD7C,
    0xCCFC7730, 0xE699E52B, 0x2503333F, 0xE560CE46, 0x097C1FF2, 0x1DFC436D, 0xBD0B771B, 0xE5FE82AC,
    0xA7D8AD78, 0xA09525C2, 0xA639123F, 0x02B6032A, 0xF6630285, 0x9F20BC92, 0xC1DDC378, 0x93BB01F7,
    0xD525B1EA, 0xE81E51E9, 0x3214523E, 0xA3C3E9B7, 0x561AE34D, 0x01C03738, 0xC3765951, 0xECE53DA8,
    0x6ACE947F, 0xC02E277C, 0xBD7A09A7, 0x86262FA8, 0x09356168, 0x4782E19C, 0x238F43EB, 0x752505C0,
    0x4A5AC809, 0x11B612B4, 0xDEDEB99C, 0xECA88F4C, 0xAEE533F3, 0xA65E47DE, 0xAA1E06D0, 0x647B686E,
    0xF73F0875, 0x922C11F7, 0x2B8E4093, 0xE53719EC, 0x1F25AEE9, 0xE22807F5, 0x44FD58F9, 0x4ABB0E55,
    0xB60D1945, 0x6E5EA63E, 0x20F670CA, 0x39FD277C, 0xABDEDA94, 0x8E76376F, 0x2F41DE2D, 0x62A02947,
    0xA77371A2, 0xB0267225, 0x17298DF5, 0x6963AEF0, 0x017E01BF, 0x806BD05B, 0x61DCF1D5, 0xBF5AC48C,
    0x8CDAF769, 0x72DB8F04, 0x3558CAA6, 0x9824C4A5, 0xDCE2A789, 0x181A9CC0, 0xC201D362, 0xEAB0C7BA,
    0x1EB6740B, 0x41CFFECD, 0xBD8BEA2C, 0x053B50B2, 0x5E0DFFED, 0x980C166D, 0x39CB8275, 0xEF606F5F,
    0x5F5A3EA6, 0x6BBE7405, 0x586069F8, 0xC3575F7A, 0xD8157384, 0x24EB5F80, 0x71154DA5, 0xE7EC6D5E,
    0xEEA0F201, 0x34E9698C, 0xCBE78B5D, 0xD5BAD20F, 0xD5EFCF19, 0x7606C3F8, 0x04D33AD8, 0xD7EA7DD9,
    0x02BE9D14, 0xD1D6A7AC, 0xFDBE831C, 0xF4F04B88, 0x9423A385, 0xBE4683F7, 0x3245A05A, 0xF0B69A5D,
    0x10902684, 0xC0709C18, 0x11CDCDCE, 0x927F1AF8, 0x9D194DE3, 0x18E70118, 0x2996B0FF, 0x73583F92,
    0xC4ECBE6F, 0xD32122D8, 0xEF674DA3, 0x30CF0437, 0x68422E47, 0xFA560394, 0xD514B48D, 0xA3C7A099,
    0x2824227B, 0xED4023E5, 0xDE57B213, 0x333AA2F0, 0xE1E0F7B4, 0x29FF81A2, 0xD009B331, 0x7639BDC9,
    0xC6D13D0D, 0x19F83103, 0x2DDA9CB5, 0x5B459F34, 0xA6D4AAED, 0x4E1E0411, 0x94F7AE6C, 0xADEB1104,
    0xB07FC6BE, 0x812942B8, 0x1B7470B5, 0xD5E36B64, 0x48482336, 0x5984B611, 0xFB885828, 0xA5BC76AD,
    0xA3253FD6, 0x27453356, 0x10329746, 0x3725158F, 0xF878BAC3, 0xE0F6ADFE, 0x8558D21D, 0x9A09AE1D,
    0x457B20C5, 0xD0A9E2ED, 0xD9A1A422, 0x138158EF, 0x451934C5, 0xBE9E817B, 0xEE41AA0F, 0xBBFB0458,
    0x018F302F, 0x44F9BEEE, 0x899FA73B, 0x762BE12A, 0x0843833D, 0xC524F5BD, 0x37BE4D1D, 0x9BFA46CB,
    0xC6F09F16, 0x4CB61B4B, 0xFE4241F9, 0xF006506C, 0x83980704, 0x84B61DC3, 0xA45678AA, 0x80F419BF,
    0xBC6BE42F, 0xF5579833, 0xB594B6E1, 0x4B31F440, 0x1074234D, 0x99F74794, 0x97C5CB09, 0x40773CDD,
    0xB71224A7, 0x9318CF09, 0xFC31098C, 0x6C56B989, 0x2B09D66C, 0xD1613A46, 0x67C57CCC, 0x1254DA02,
    0x77CA4685, 0x43B3EAB9, 0x5438E86A, 0x17107EDA, 0x8234CAB1, 0x563D94DD, 0xC7355E8D, 0x90F9A5FC,
    0x156BA1E5, 0x28DE2C9C, 0xFAAB8FC9, 0x9A5A446C, 0x0D042329, 0x5DF3BC21, 0x95AE4A78, 0x45367FA2,
    0x8501FA08, 0xDBE3CE56, 0x2A6ABB4C, 0xB566E4C7, 0x3BBDECA5, 0x6E5FCCEF, 0x8246AA44, 0x29A1D56D,
    0x260B81D4, 0x926B39F7, 0x75ECB709, 0x06E82EF9, 0x652C2DB7, 0x12FC5CD7, 0x27ADD593, 0x2E37FEE7,
    0x8FAA3C11, 0x32124637, 0xFE8384AE, 0x50E374A8, 0x31043B6B, 0x71E7B1BC, 0x931B4DEA, 0x00B838E8,
    0xF59131B0, 0x4EFA7058, 0x3FF97734, 0xBD89C80C, 0x43377D47, 0x410783C5, 0xD223823B, 0x9065C23C,
    0xE92C8802, 0x6ED7F8AE, 0x1952BFF3, 0xFE1671BE, 0xA1445A36, 0x64DC1A84, 0xBCA5D2E0, 0x687B6F8E,
    0x8DCD77D3, 0xBDC95C5F, 0xF044A0F6, 0x1956085A, 0x86D4F4CE, 0x1D4959A7, 0xC5FA2991, 0x040CAF10,
    0x0BC1753B, 0x9E42DAB9, 0xE26850B0, 0xD0CF49B3, 0x650C5EE2, 0x203477D1, 0xCA0FFA21, 0x98F81713,
    0xB1E1343C, 0xE200CC29, 0x8F78EB3C, 0xA43B24A7, 0x49AC5EE2, 0x381CDB9D, 0x00C7E627, 0x94E5B120,
    0x63AF599D, 0xCA6B15EF, 0xA45BEE6D, 0xCAE09D89, 0x82D68B8C, 0xB89E3BCE, 0x6C734A99, 0x6C7AE5D7,
    0x5760AD5C, 0xE2787A4E, 0x791313D6, 0x3F147875, 0x738B8076, 0xA926D787, 0x36157259, 0x888494AE,
    0xD0E7AB0C, 0x12DC6525, 0x5029E715, 0x78CB4960, 0xE43F55B9, 0xD93FB4F8, 0x1DE1270E, 0x83AC5601,
    0xC9B8E507, 0x75C65EC7, 0x95B973F4, 0x9F6359A6, 0xD72C1E0A, 0x2FBBDD03, 0x7CD8355E, 0x90A88C93,
    0xD75FD14F, 0xAAF3B740, 0x4A6DCF79, 0xC84B79E4, 0x9D67C6DF, 0xB0708CDF, 0x70B717CE, 0x7CF15940,
    0xE615EED0, 0xB1CF70D8, 0x6862B2AD, 0x35C29C9A, 0xC926FE74, 0x10F14EC3, 0x578D0B76, 0xA3E85245,
    0xA6B0432C, 0x35A70C35, 0x51C16A94, 0x8E3EFE48, 0xBF61E2E5, 0x9ADE57D2, 0xDBE87605, 0x894E88CC,
    0x5FAE3426, 0xBD0378B8, 0x8F46B88D, 0xBEAA2111, 0x0B550FE6, 0xF3F86BB9, 0x590C8B3B, 0x8FE3D624,
    0x01B2AE8B, 0x8ED8AA1E, 0x2121C3B1, 0x4170AD19, 0x95FA6410, 0x306203F1, 0xC42CFA3B, 0xEC95B38D,
    0xC8E97BF8, 0x995B7974, 0x5797C079, 0x7279F56E, 0x40535896, 0x97F31D52, 0xCF6B6EFA, 0x29E36D1A,
    0x6BC4360E, 0x1F5D075E, 0xB5ABE8E0, 0x73BD527C, 0xBDC0CAEE, 0x2FCA3439, 0xAC158E3F, 0x5162C831,
    0xBAA03FD4, 0xE8681EF3, 0xF050E351, 0x61BE1BC8, 0x1B8924D1, 0xF359497E, 0xFB675803, 0xFAFA6969,
    0x1BD7E5AE, 0x78ABE0CE, 0xD5EDAC01, 0x14D20C79, 0x94DB9B56, 0xBE99714E, 0x4AF7878F, 0x122F2F03,
    0x83FE0872, 0x9615AAA7, 0x2A2498C0, 0x1C1DA978, 0xC35BF48A, 0xCCD8A0D1, 0xCE77E888, 0xE45F64AA,
    0x4487ED16, 0xB9403459, 0xF10149A1, 0x7ECAD37B, 0xE5C7AEEA, 0x793BF2B9, 0x4CB21DC5, 0xEDF85077,
    0x6057ABD1, 0x5BDF092A, 0x67E534C0, 0xD0656104, 0x4463E438, 0x00224F00, 0xE3FFE54A, 0xB763DFCF,
    0xB58DB016, 0x1DAEDE7A, 0xF78693A4, 0xA7B1EA2B, 0xB9F29135, 0xA3647580, 0x0FDC63E3, 0x6F48A15E,
    0xE1BE1BD5, 0x676BCE86, 0x77183864, 0x064C47E6, 0x6442C895, 0x0CA8E797, 0x3734E951, 0xF0587109,
    0x3A8D93F6, 0x298A8763, 0xB4CE3D8C, 0xB5FC9F6B, 0xEB55CC34, 0xEEA4A256, 0x4117A8F9, 0xD4494E16,
    0x4B1AF706, 0x451B2152, 0xFB1369C9, 0xC56179DC, 0xD82667E1, 0x0409415C, 0x36B8AAE3, 0x5DA5B221,
    0x6416C150, 0xC6AD3978, 0x3AA4CF8F, 0x92D9CE71, 0x94434AE1, 0x843A142D, 0xE967AC8D, 0x74A2C72E,
    0xC71F1D76, 0x127CDEF2, 0xA8F89D15, 0x66217E0C, 0xDE40E4B1, 0x0DF204FF, 0x33CCEC4E, 0xFFA4010A,
    0x9E046DC9, 0x7D9B8830, 0xA7C97AE5, 0xD1E09827, 0x282B691B, 0x42D7A075, 0x9028B59C, 0x11A99F93,
    0xF978A706, 0xCA1EBAA0, 0x6F4CE324, 0x3D67A545, 0xB34B83DC, 0xB5BAE4D2, 0x8D5A1E13, 0xD3C4E7D7,
    0xFC4CB29E, 0x86E355C6, 0x29C28275, 0x6C785D4D, 0x4E68597F, 0x2F3B84DF, 0x2CD0EC84, 0x2B8DB068,
    0x09080ADB, 0xE5339B93, 0x4121E5A9, 0x8BF74878, 0x7DAB0E3B, 0xE36014B0, 0xEE4D94FF, 0xCFC6EDA4,
    0xBBF09C6B, 0x44AD54BF, 0x09002389, 0x7E066644, 0xBBAA31E7, 0xCA3E12AF, 0x4F868CCD, 0xCF66A3FD,
    0xFF04C32D, 0xA1B8EEF7, 0x557C3A55, 0x146C4C48, 0xDC0AE619, 0x9C838205, 0x4CE56B4B, 0xB65BEB48,
    0xEADD51B2, 0x720ECAEF, 0x930C59AA, 0x3EA54588, 0x217E4671, 0x79381076, 0x2C0E8267, 0xFA603793,
    0xAC18C230, 0x25B73579, 0xCC0A7C09, 0xD3FF19ED, 0x1E29687D, 0xD342A269, 0x62320599, 0xE8625E58,
    0x41145969, 0x92DEFAD5, 0x783B3540, 0x8DC3B30E, 0xEA05D388, 0xDD6E80E4, 0x1B740DAE, 0x55492B16,
    0xC84C35CF, 0x01AAB686, 0x6C15CCDF, 0x3BD0A308, 0x9711BF3E, 0x434BCB23, 0x0FEBA9C2, 0xBFD39959,
    0xA0C1F88E, 0x7A746D9F, 0x292BADFE, 0xAC8E8FC3, 0x47735CF6, 0xC567D657, 0x5B495FD9, 0x65088777,
    0xE9287AE2, 0xC63EAE26, 0x67623D30, 0x15F08A60, 0xA9DC1380, 0xB29A6CBE, 0x404C7021, 0x74A7F30B,
    0xFD948534, 0x811BA8DA, 0x039DED43, 0xCCFD8049, 0x1EC7DC54, 0x232D1997, 0x1AA00300, 0xB9917B0A
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
            // Inject KSC constant
            for (r = 0; r < 4; r++) {
                for (c = 0; c < 8; c++) {
                    KSS[r][c] ^= KSC[i * 32 + r * 8 + c];
                }
            }
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
        0x35,0x58,0x91,0x33,0x62,0x14,0xF3,0xD6,
        0xD0,0xDC,0xE1,0x82,0x13,0x14,0x74,0x0E,
        0x69,0x78,0x60,0xF2,0x7E,0x9C,0x38,0x3F,
        0x44,0x84,0xDD,0x34,0x8B,0xFF,0x02,0x5E,
        0xF1,0x85,0x78,0x95,0xB2,0xCA,0x4E,0xD3,
        0x38,0x8F,0x9C,0x51,0x12,0xAB,0x2C,0x96,
        0xEF,0xFF,0x69,0x4A,0xB3,0xB8,0x1F,0x68,
        0xBF,0xC9,0xD2,0x40,0xCA,0xF0,0x33,0xF4
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
