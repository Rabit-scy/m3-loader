/*
 * CSE_ext_ECC_ECDSA_SignVerif_P521_TV.c
 */


/*#  CAVS 11.0*/
/*#  "SigVer" information*/
/*#  Curves/SHAs selected: P-256,SHA-256 P-256,SHA-384 P-256,SHA-512 P-384,SHA-384 P-384,SHA-512 P-521,SHA-512 */
/*#  Generated on Wed Mar 16 16:16:55 2011*/

#include "config.h"
#include "CSE_ext_hash.h"
#include "CSE_ext_ECC_ECDSA_SignGenVerif_TV.h"

#ifdef INCLUDE_NIST_P521
const verify_test_vect_stt verify_test_vect_array_P521[NB_OF_ECDSA_SIGN_VERIF_TV_P521] =
{
#ifdef INCLUDE_SHA512
    { /* TV 1-1*/
      C_NIST_P_521, E_SHA512,
      /* Msg */
      {0xa0,0x73,0x2a,0x60,0x5c,0x78,0x5a,0x2c,0xc9,0xa3,0xff,0x84,0xcb,0xaf,0x29,0x17,
       0x50,0x40,0xf7,0xa0,0xcc,0x35,0xf4,0xea,0x8e,0xef,0xf2,0x67,0xc1,0xf9,0x2f,0x06,
       0xf4,0x6d,0x3b,0x35,0x43,0x71,0x95,0x18,0x5d,0x32,0x2c,0xbd,0x77,0x5f,0xd2,0x47,
       0x41,0xe8,0x6e,0xe9,0x23,0x6b,0xa5,0xb3,0x74,0xa2,0xac,0x29,0x80,0x35,0x54,0xd7,
       0x15,0xfa,0x46,0x56,0xac,0x31,0x77,0x8f,0x10,0x3f,0x88,0xd6,0x84,0x34,0xdd,0x20,
       0x13,0xd4,0xc4,0xe9,0x84,0x8a,0x11,0x19,0x8b,0x39,0x0c,0x3d,0x60,0x0d,0x71,0x28,
       0x93,0x51,0x3e,0x17,0x9c,0xd3,0xd3,0x1f,0xb0,0x6c,0x6e,0x2a,0x10,0x16,0xfb,0x96,
       0xff,0xd9,0x70,0xb1,0x48,0x9e,0x36,0xa5,0x56,0xab,0x3b,0x53,0x7e,0xb2,0x9d,0xff },
      /* Qx */
      {0x01,0x2a,0x59,0x3f,0x56,0x8c,0xa2,0x57,0x1e,0x54,0x3e,0x00,0x06,0x6e,0xcd,0x3a,
       0x32,0x72,0xa5,0x7e,0x1c,0x94,0xfe,0x31,0x1e,0x5d,0xf9,0x6a,0xfc,0x1b,0x79,0x2e,
       0x58,0x62,0x72,0x0f,0xc7,0x30,0xe6,0x20,0x52,0xbb,0xf3,0xe1,0x18,0xd3,0xa0,0x78,
       0xf0,0x14,0x4f,0xc0,0x0c,0x9d,0x8b,0xaa,0xaa,0x82,0x98,0xff,0x63,0x98,0x1d,0x09,
       0xd9,0x11 },
      /* Qy */
      {0x01,0x7c,0xea,0x5a,0xe7,0x5a,0x74,0x10,0x0e,0xe0,0x3c,0xdf,0x24,0x68,0x39,0x3e,
       0xef,0x55,0xdd,0xab,0xfe,0x8f,0xd5,0x71,0x8e,0x88,0x90,0x3e,0xb9,0xfd,0x24,0x1e,
       0x8c,0xbf,0x9c,0x68,0xae,0x16,0xf4,0xa1,0xdb,0x26,0xc6,0x35,0x2a,0xfc,0xb1,0x89,
       0x4a,0x98,0x12,0xda,0x6d,0x32,0xcb,0x86,0x20,0x21,0xc8,0x6c,0xd8,0xaa,0x48,0x3a,
       0xfc,0x26 },
      /* R */
      {0x01,0xaa,0xc7,0x69,0x2b,0xaf,0x3a,0xa9,0x4a,0x97,0x90,0x73,0x07,0x01,0x08,0x95,
       0xef,0xc1,0x33,0x7c,0xdd,0x68,0x6f,0x9e,0xf2,0xfd,0x84,0x04,0x79,0x6a,0x74,0x70,
       0x1e,0x55,0xb0,0x3c,0xee,0xf4,0x1f,0x3e,0x6f,0x50,0xa0,0xee,0xea,0x11,0x86,0x9c,
       0x47,0x89,0xa3,0xe8,0xab,0x5b,0x77,0x32,0x49,0x61,0xd0,0x81,0xe1,0xa3,0x37,0x7c,
       0xcc,0x91 },
      /* S */
      {0x00,0x09,0xc1,0xe7,0xd9,0x3d,0x05,0x6b,0x5a,0x97,0x75,0x94,0x58,0xd5,0x8c,0x49,
       0x13,0x4a,0x45,0x07,0x18,0x54,0xb8,0xa6,0xb8,0x27,0x2f,0x9f,0xe7,0xe7,0x8e,0x1f,
       0x3d,0x80,0x97,0xe8,0xa6,0xe7,0x31,0xf7,0xab,0x48,0x51,0xeb,0x26,0xd5,0xaa,0x4f,
       0xda,0xdb,0xa6,0x29,0x6d,0xc7,0xaf,0x83,0x5f,0xe3,0xd1,0xb6,0xdb,0xa4,0xb0,0x31,
       0xd5,0xf3 },
      /* Result */
      TEST_FAIL
    }, /* previous group sep */


    { /* TV 1-2*/
      C_NIST_P_521, E_SHA512,
      /* Msg */
      {0x2f,0xc1,0x14,0x0a,0x74,0x14,0xe3,0x3a,0xb4,0x69,0x79,0x9f,0x94,0x32,0xb3,0x0d,
       0x29,0xd1,0xe4,0x45,0x1b,0x28,0xa7,0x56,0xa0,0xf2,0x4a,0x7f,0x7f,0x90,0xcb,0x28,
       0x4f,0xb4,0x43,0xc0,0x74,0x26,0x7a,0x76,0x00,0xb3,0x70,0xee,0xff,0xfe,0xa2,0x30,
       0x78,0xb4,0x01,0x6b,0x59,0xcb,0xeb,0x95,0xfa,0xb3,0xc6,0xf3,0x7a,0x72,0xe9,0x22,
       0x71,0xb2,0x9e,0xe2,0x38,0x2e,0x11,0x06,0xf8,0xdf,0xd3,0x87,0x1e,0xf9,0xbf,0x04,
       0x5f,0x78,0xd3,0x78,0xac,0xc8,0xd1,0x6c,0x98,0x3d,0x54,0xc7,0xbc,0x0b,0x0c,0xb4,
       0x6b,0xba,0x0d,0xe7,0x86,0x30,0xf6,0xd0,0x79,0x6c,0x2c,0x27,0x5e,0x46,0xeb,0xc8,
       0x8e,0x6e,0x6c,0x0e,0x67,0x5e,0xbd,0x84,0x9f,0x02,0xe4,0x7f,0x51,0xab,0xd2,0x15 },
      /* Qx */
      {0x01,0xd6,0xae,0xf4,0x43,0x70,0x32,0x5a,0x8a,0x58,0x82,0xf4,0x66,0x7c,0x21,0x17,
       0x2c,0xdc,0x8f,0xa4,0x1d,0x71,0x25,0x62,0x88,0x3e,0xce,0xcf,0xf5,0x38,0x83,0xac,
       0x8e,0xe2,0x76,0x12,0x4e,0x82,0x50,0x88,0xc7,0x9d,0x6c,0x9d,0x96,0x32,0x3c,0xb7,
       0xb8,0xc0,0xb7,0xea,0x44,0xd3,0xf0,0x02,0x6e,0x25,0x38,0xf4,0xb6,0x2d,0x78,0x5b,
       0xb1,0xaf },
      /* Qy */
      {0x00,0x27,0x20,0x39,0x59,0xa6,0xe9,0x44,0xb9,0x1f,0xe6,0x30,0x6d,0xeb,0xe7,0x4d,
       0xc5,0xdd,0xe9,0x83,0x1f,0xd0,0xec,0x27,0xe8,0xbe,0x2d,0x0b,0x56,0x80,0x7d,0x63,
       0x15,0x1b,0x15,0xf6,0x49,0x5b,0x86,0x32,0xe9,0x19,0xe1,0xe6,0xb0,0x15,0xf5,0xae,
       0x5f,0x2b,0x6f,0xb8,0xcf,0x75,0xb5,0xf8,0x48,0xf0,0x0c,0xf4,0xee,0x45,0x7c,0xeb,
       0xed,0x3a },
      /* R */
      {0x00,0x44,0x17,0xff,0x74,0x88,0x9d,0xde,0x6b,0xb1,0x82,0x0b,0x5d,0x13,0xda,0x5c,
       0x81,0xdc,0xf9,0xb0,0x72,0x3e,0xe8,0x9b,0xb1,0xff,0x0d,0x3f,0xaa,0x90,0xd4,0x97,
       0x68,0x57,0x09,0xf3,0x15,0xb2,0xcb,0xe5,0x54,0x81,0xde,0xe4,0x3e,0xbb,0x6d,0x25,
       0xb1,0x50,0x1a,0xe6,0x94,0x94,0xdd,0x69,0xe7,0xbf,0xfb,0x72,0xf9,0x87,0xd1,0x57,
       0x3b,0x93 },
      /* S */
      {0x00,0xfd,0x7a,0xa0,0x27,0xc6,0x65,0x45,0x8c,0x7a,0xc1,0x1d,0x54,0xd4,0xf3,0x2c,
       0xb4,0xa1,0xe7,0x27,0xb4,0x99,0xce,0x27,0xb0,0x8d,0x3d,0x64,0x7c,0x63,0x6c,0xc3,
       0x22,0x2a,0x4f,0x0a,0x60,0x57,0x73,0x22,0x49,0xdd,0xc2,0x25,0x74,0xd7,0xcb,0x80,
       0xc3,0x76,0x9c,0x3e,0xa9,0xde,0x3d,0x33,0xdb,0x3e,0xdd,0x8e,0xa9,0x0c,0xb3,0xf8,
       0xdc,0x8a },
      /* Result */
       TEST_FAIL
    }, /* previous group sep */

    { /* TV 1-3*/
      C_NIST_P_521, E_SHA512,
      /* Msg */
      {0xf6,0x94,0x17,0xbe,0xad,0x3b,0x1e,0x20,0x8c,0x4c,0x99,0x23,0x6b,0xf8,0x44,0x74,
       0xa0,0x0d,0xe7,0xf0,0xb9,0xdd,0x23,0xf9,0x91,0xb6,0xb6,0x0e,0xf0,0xfb,0x3c,0x62,
       0x07,0x3a,0x5a,0x7a,0xbb,0x1e,0xf6,0x9d,0xbb,0xd8,0xcf,0x61,0xe6,0x42,0x00,0xca,
       0x08,0x6d,0xfd,0x64,0x5b,0x64,0x1e,0x8d,0x02,0x39,0x77,0x82,0xda,0x92,0xd3,0x54,
       0x2f,0xbd,0xdf,0x63,0x49,0xac,0x0b,0x48,0xb1,0xb1,0xd6,0x9f,0xe4,0x62,0xd1,0xbb,
       0x49,0x2f,0x34,0xdd,0x40,0xd1,0x37,0x16,0x38,0x43,0xac,0x11,0xbd,0x09,0x9d,0xf7,
       0x19,0x21,0x2c,0x16,0x0c,0xbe,0xbc,0xb2,0xab,0x6f,0x35,0x25,0xe6,0x48,0x46,0xc8,
       0x87,0xe1,0xb5,0x2b,0x52,0xec,0xed,0x94,0x47,0xa3,0xd3,0x19,0x38,0x59,0x3a,0x87 },
      /* Qx */
      {0x01,0x53,0xeb,0x2b,0xe0,0x54,0x38,0xe5,0xc1,0xef,0xfb,0x41,0xb4,0x13,0xef,0xc2,
       0x84,0x3b,0x92,0x7c,0xbf,0x19,0xf0,0xbc,0x9c,0xc1,0x4b,0x69,0x3e,0xee,0x26,0x39,
       0x4a,0x0d,0x88,0x80,0xdc,0x94,0x6a,0x06,0x65,0x6b,0xcd,0x09,0x87,0x15,0x44,0xa5,
       0xf1,0x5c,0x7a,0x1f,0xa6,0x8e,0x00,0xcd,0xc7,0x28,0xc7,0xcf,0xb9,0xc4,0x48,0x03,
       0x48,0x67 },
      /* Qy */
      {0x01,0x43,0xae,0x8e,0xec,0xbc,0xe8,0xfc,0xf6,0xb1,0x6e,0x61,0x59,0xb2,0x97,0x0a,
       0x9c,0xeb,0x32,0xc1,0x7c,0x1d,0x87,0x8c,0x09,0x31,0x73,0x11,0xb7,0x51,0x9e,0xd5,
       0xec,0xe3,0x37,0x4e,0x79,0x29,0xf3,0x38,0xdd,0xd0,0xec,0x05,0x22,0xd8,0x1f,0x2f,
       0xa4,0xfa,0x47,0x03,0x3e,0xf0,0xc0,0x87,0x2d,0xc0,0x49,0xbb,0x89,0x23,0x3e,0xef,
       0x9b,0xc1 },
      /* R */
      {0x00,0xdd,0x63,0x39,0x47,0x44,0x6d,0x0d,0x51,0xa9,0x6a,0x01,0x73,0xc0,0x11,0x25,
       0x85,0x8a,0xbb,0x2b,0xec,0xe6,0x70,0xaf,0x92,0x2a,0x92,0xde,0xdc,0xec,0x06,0x71,
       0x36,0xc1,0xfa,0x92,0xe5,0xfa,0x73,0xd7,0x11,0x6a,0xc9,0xc1,0xa4,0x2b,0x9c,0xb6,
       0x42,0xe4,0xac,0x19,0x31,0x0b,0x04,0x9e,0x48,0xc5,0x30,0x11,0xff,0xc6,0xe7,0x46,
       0x1c,0x36 },
      /* S */
      {0x00,0xef,0xbd,0xc6,0xa4,0x14,0xbb,0x8d,0x66,0x3b,0xb5,0xcd,0xb7,0xc5,0x86,0xbc,
       0xcf,0xe7,0x58,0x90,0x49,0x07,0x6f,0x98,0xce,0xe8,0x2c,0xdb,0x5d,0x20,0x3f,0xdd,
       0xb2,0xe0,0xff,0xb7,0x79,0x54,0x95,0x9d,0xfa,0x5e,0xd0,0xde,0x85,0x0e,0x42,0xa8,
       0x6f,0x5a,0x63,0xc5,0xa6,0x59,0x2e,0x9b,0x9b,0x8b,0xd1,0xb4,0x05,0x57,0xb9,0xcd,
       0x0c,0xc0 },
      /* Result */
      TEST_PASS
    }, /* previous group sep */

    { /* TV 1-4*/
      C_NIST_P_521, E_SHA512,
      /* Msg */
      {0x36,0x07,0xea,0xa1,0xdb,0x2f,0x69,0x6b,0x93,0xd5,0x73,0xf6,0x7f,0x03,0x59,0x42,
       0x21,0x01,0xcc,0x6c,0xeb,0x52,0x6a,0x5e,0xc8,0x7b,0x24,0x9e,0x5b,0x79,0x1a,0xc4,
       0xdf,0x48,0x8f,0x48,0x32,0xeb,0x00,0xc6,0xec,0x94,0xbb,0x52,0xb7,0xdd,0x9d,0x95,
       0x3a,0x9c,0x3c,0xed,0x3f,0xb7,0x17,0x1d,0x28,0xc4,0x2f,0x81,0xfd,0x99,0x98,0xcd,
       0x7d,0x35,0xc7,0x03,0x09,0x75,0x38,0x1e,0x54,0xe0,0x71,0xa3,0x7e,0xb4,0x1d,0x3e,
       0x41,0x9f,0xe9,0x35,0x76,0xd1,0x41,0xe3,0x6a,0x98,0x00,0x89,0xdb,0x54,0xeb,0xbf,
       0x3a,0x3e,0xbf,0x8a,0x07,0x6d,0xaf,0x8e,0x57,0xce,0x44,0x84,0xd7,0xf7,0xd2,0x34,
       0xe1,0xf6,0xd6,0x58,0xda,0x51,0x03,0xa6,0xe1,0xd6,0xae,0x96,0x41,0xec,0xac,0x79 },
      /* Qx */
      {0x01,0x18,0x4b,0x27,0xa4,0x8e,0x22,0x38,0x91,0xcb,0xd1,0xf4,0xa0,0x25,0x57,0x47,
       0xd0,0x78,0xf8,0x27,0x68,0x15,0x7e,0x5a,0xdc,0xc8,0xe7,0x83,0x55,0xa2,0xff,0x17,
       0xd8,0x36,0x3d,0xfa,0x39,0xbc,0xdb,0x48,0xe2,0xfa,0xe7,0x59,0xea,0x3b,0xd6,0xa8,
       0x90,0x9c,0xe1,0xb2,0xe7,0xc2,0x06,0x53,0x91,0x5b,0x7c,0xd7,0xb9,0x4d,0x8f,0x11,
       0x03,0x49 },
      /* Qy */
      {0x00,0x3b,0xd6,0xe2,0x73,0xee,0x42,0x78,0x74,0x3f,0x1b,0xb7,0x1f,0xf7,0xae,0xfe,
       0x1f,0x2c,0x52,0x95,0x4d,0x67,0x4c,0x96,0xf2,0x68,0xf3,0x98,0x5e,0x69,0x72,0x7f,
       0x22,0xad,0xbe,0x31,0xe0,0xdb,0xe0,0x1d,0xa9,0x1e,0x3e,0x6d,0x19,0xba,0xf8,0xef,
       0xa4,0xdc,0xb4,0xd1,0xca,0xcd,0x06,0xa8,0xef,0xe1,0xb6,0x17,0xbd,0x68,0x18,0x39,
       0xe6,0xb9 },
      /* R */
      {0x00,0x4c,0x1d,0x88,0xd0,0x38,0x78,0xf9,0x67,0x13,0x3e,0xb5,0x67,0x14,0x94,0x5d,
       0x3c,0x89,0xc3,0x20,0x0f,0xad,0x08,0xbd,0x2d,0x3b,0x93,0x01,0x90,0x24,0x6b,0xf8,
       0xd4,0x3e,0x45,0x36,0x43,0xc9,0x4f,0xda,0xb9,0xc6,0x46,0xc5,0xa1,0x12,0x71,0xc8,
       0x00,0xd5,0xdf,0x25,0xc1,0x19,0x27,0xc0,0x00,0x26,0x3e,0x78,0x52,0x51,0xd6,0x2a,
       0xcd,0x59 },
      /* S */
      {0x01,0x2e,0x31,0x76,0x6a,0xf5,0xc6,0x05,0xa1,0xa6,0x78,0x34,0x70,0x20,0x52,0xe7,
       0xe5,0x6b,0xbd,0x9e,0x23,0x81,0x16,0x3a,0x9b,0xf1,0x6b,0x57,0x99,0x12,0xa9,0x8b,
       0xeb,0xab,0xb7,0x05,0x87,0xda,0x58,0xbe,0xc6,0x21,0xc1,0xe7,0x79,0xa8,0xa2,0x1c,
       0x19,0x3d,0xda,0x07,0x85,0x01,0x8f,0xd5,0x80,0x34,0xf9,0xa6,0xac,0x3e,0x29,0x7e,
       0x37,0x90 },
      /* Result */
       TEST_FAIL
    }, /* previous group sep */

    { /* TV 1-5*/
      C_NIST_P_521, E_SHA512,
      /* Msg */
      {0x30,0x7b,0xfa,0x6a,0x27,0x64,0x59,0x1b,0xc3,0x15,0x37,0xfc,0xbc,0x72,0x75,0xe2,
       0x58,0xf1,0x58,0xf4,0xb7,0xac,0x5c,0xb0,0x37,0x61,0xaa,0xfe,0xe8,0xff,0x0c,0x58,
       0xa9,0x33,0xcd,0x28,0xa3,0x8f,0xcd,0x1a,0x29,0xa7,0xc9,0x07,0x05,0x0c,0x27,0x3b,
       0xff,0xb2,0x49,0x30,0x3e,0xa0,0x00,0x7d,0x16,0xc8,0xc4,0xaa,0xaf,0x14,0x5a,0xfe,
       0x9c,0xc9,0x72,0x85,0xd3,0x3a,0x8b,0xd4,0x2f,0x56,0x6b,0x1b,0xea,0x7a,0x5e,0xf7,
       0x78,0x44,0xe3,0xd7,0xc3,0xb5,0x51,0x32,0xac,0x74,0x07,0xda,0x04,0xf1,0xa7,0xe8,
       0x5e,0xc7,0xf2,0xd0,0x3b,0x66,0x7d,0x9c,0x3c,0x52,0xeb,0xeb,0x1d,0x25,0xb3,0x92,
       0xfb,0x4a,0xa2,0x10,0xaf,0xf2,0xda,0xc0,0x0f,0xfd,0x1b,0x14,0xb0,0xe2,0x11,0x2f },
      /* Qx */
      {0x01,0xd9,0x02,0x0b,0x8e,0x67,0x17,0x25,0x4e,0xeb,0xe6,0x19,0xd4,0x6d,0xd5,0xa9,
       0xdd,0xa7,0xba,0x54,0x91,0xa7,0xd1,0xb6,0x82,0x0f,0xba,0x88,0x8e,0x23,0x6f,0xaf,
       0xd7,0x11,0x79,0x20,0x04,0x37,0xf4,0xd6,0x12,0x84,0xfb,0x5a,0x3d,0xfb,0xad,0xa6,
       0x6b,0xac,0x3e,0x69,0x09,0xcc,0xbe,0xee,0x03,0xc2,0xb9,0x3a,0x8b,0xeb,0xe4,0x1a,
       0x73,0xf4 },
      /* Qy */
      {0x00,0x48,0xa5,0xf0,0x91,0x74,0xfd,0xa1,0x27,0x04,0xac,0xdd,0x8e,0xd5,0x60,0x69,
       0x5d,0xec,0x42,0x86,0x4b,0x63,0x00,0xa0,0x30,0x76,0x8a,0x0b,0xe7,0xf0,0x9d,0x25,
       0xf8,0x2d,0x7b,0x12,0x61,0x25,0xe4,0x14,0x17,0xa1,0x45,0x64,0x19,0x37,0x80,0x7e,
       0xd8,0xd1,0xaf,0x7a,0x53,0xf5,0xbc,0x3f,0xc3,0xc5,0x74,0x27,0xd7,0x55,0xdc,0xce,
       0x3e,0x25 },
      /* R */
      {0x00,0x92,0xdf,0x2d,0xcb,0x45,0x7f,0xc7,0x57,0x8e,0xaa,0xcc,0x98,0xff,0xd7,0x3a,
       0xde,0x07,0xd7,0x64,0xe9,0x55,0x35,0x06,0xf3,0xdc,0x95,0x8c,0xdb,0x3f,0x65,0xd3,
       0x76,0x65,0x52,0x8c,0xb2,0xf5,0xf8,0xbd,0xed,0x0d,0xb0,0xa5,0x7e,0x6f,0xa7,0x3b,
       0xfa,0xd1,0xaa,0xf9,0x47,0x18,0x37,0x9d,0x16,0x55,0xdb,0x4f,0x32,0xd4,0xc5,0x05,
       0xa7,0x85 },
      /* S */
      {0x01,0x0e,0x0c,0x31,0x47,0x9c,0x2b,0x29,0xdc,0x27,0x26,0xfe,0x9f,0x75,0xb3,0x97,
       0xd9,0xe3,0x7a,0x17,0x61,0x9e,0x96,0xbc,0x63,0x1c,0x62,0xe9,0xec,0xe7,0x1f,0x05,
       0xb1,0x99,0x80,0x4c,0xc8,0x03,0x94,0x0d,0x43,0xdd,0xee,0x41,0x17,0x1d,0xd7,0x78,
       0x76,0x68,0xc7,0xdb,0x05,0x04,0x9d,0xd5,0xb6,0x3e,0x4f,0x63,0x56,0x2a,0xa7,0x00,
       0xca,0x81 },
      /* Result */
       TEST_FAIL
    }, /* previous group sep */

    { /* TV 1-6*/
      C_NIST_P_521, E_SHA512,
      /* Msg */
      {0x36,0x29,0xce,0x61,0x37,0xcf,0xfa,0xf0,0xa4,0x85,0x59,0x4c,0xd4,0x70,0x49,0xe7,
       0x86,0x6f,0xa8,0x1b,0xb5,0x6d,0xd6,0x61,0x68,0x56,0x75,0x42,0xc6,0xb8,0xfd,0xf7,
       0xdb,0xaf,0xe6,0x93,0xc9,0x19,0xa7,0x28,0x8a,0x03,0xf2,0x48,0x3b,0x09,0xc9,0xcd,
       0x2b,0x3f,0x91,0x67,0x02,0x64,0x67,0x29,0x67,0xe4,0x54,0x2d,0x5b,0xb6,0xc8,0x7e,
       0x86,0x11,0x15,0xff,0x3e,0xc2,0xec,0x2e,0x96,0x53,0x51,0x48,0x62,0x3e,0x80,0x52,
       0x5a,0xba,0xe8,0xd7,0x1f,0x29,0x6a,0x4e,0x89,0x47,0xb4,0x8b,0xb6,0x40,0x74,0xeb,
       0xb7,0xe0,0xc7,0xa5,0x86,0xf5,0x7b,0x35,0xda,0x91,0x07,0x04,0xf4,0x4b,0x41,0x15,
       0x1a,0xc6,0xdb,0x35,0x0c,0x47,0xe8,0x18,0x05,0xfc,0x69,0x32,0xf4,0x35,0xa9,0x8a },
      /* Qx */
      {0x00,0x07,0x06,0x7d,0x2c,0xf7,0xb7,0x61,0x9b,0x9f,0xcf,0xf2,0xc8,0x98,0x24,0x6a,
       0xe0,0x95,0x04,0x39,0xb8,0xba,0xb9,0x2d,0x80,0x96,0x24,0x97,0x0e,0xda,0x18,0x45,
       0x6c,0xb9,0x99,0x53,0xce,0x1a,0xe4,0x5e,0xe5,0xd3,0x6e,0xf0,0x2f,0xcd,0x5c,0xaa,
       0x4d,0x95,0x1d,0xe8,0x58,0x1f,0x0c,0x21,0xe5,0x72,0xca,0xad,0x56,0xd6,0xdc,0xe6,
       0x0d,0xa3 },
      /* Qy */
      {0x01,0x91,0x3c,0x59,0x00,0x7a,0x30,0x90,0x05,0xf2,0x26,0xb6,0xa3,0x01,0x22,0x82,
       0x8d,0x60,0xb4,0xd0,0x39,0x03,0x59,0xe1,0x97,0x7f,0x88,0xb5,0x34,0x7d,0xac,0xf2,
       0x05,0x6d,0xd3,0x62,0x64,0x8e,0x8b,0x1d,0x6f,0xc0,0x38,0xa3,0xbd,0x3f,0xde,0x6f,
       0x11,0x40,0xc7,0x40,0xef,0xa9,0x07,0x5a,0xb8,0xb4,0xa6,0x4b,0x33,0x4c,0x5c,0xd4,
       0x3f,0x09 },
      /* R */
      {0x01,0x2a,0xa4,0xa5,0x32,0xc1,0x08,0xaa,0x3c,0xfb,0x17,0x53,0xf9,0x5c,0xa6,0x26,
       0xbb,0x72,0xbd,0x96,0xa4,0x23,0xd7,0x27,0x65,0x6d,0x4e,0xbd,0xc3,0xf4,0x06,0xd6,
       0xcc,0x6c,0x44,0xd3,0x71,0x8f,0x9a,0xba,0xe8,0xa0,0xb4,0x6b,0xe9,0xb5,0x7f,0x8f,
       0xd3,0xa5,0x40,0x32,0x6b,0x63,0xd0,0xd4,0xa8,0xa9,0x31,0x65,0x71,0x59,0x20,0x43,
       0x77,0x87 },
      /* S */
      {0x00,0x1b,0xad,0xaf,0x38,0xe1,0x6e,0xfd,0x75,0x91,0x5f,0x48,0x06,0xf0,0x54,0xd4,
       0x0a,0xbd,0x2d,0x11,0xe4,0x02,0x03,0x9b,0xd4,0x8c,0x83,0x2f,0x66,0xcb,0xfd,0x14,
       0x5e,0x4d,0xac,0x93,0x35,0x7d,0x47,0x6b,0x7e,0x60,0x8d,0x7b,0x75,0xa0,0x17,0x37,
       0x4a,0xe7,0x6e,0xee,0x86,0xc5,0x05,0xf2,0xcc,0x16,0xea,0xa1,0x90,0x75,0x82,0x7c,
       0xcd,0x60 },
      /* Result */
       TEST_FAIL
    }, /* previous group sep */

    { /* TV 1-7*/
      C_NIST_P_521, E_SHA512,
      /* Msg */
      {0x27,0x38,0x3a,0x92,0x3d,0x22,0x29,0x2d,0xac,0xff,0x10,0x5f,0x00,0xd0,0x43,0x3e,
       0xb7,0x19,0xcc,0x5f,0xdf,0x0d,0x55,0x5f,0x05,0xa7,0x5f,0xef,0x39,0x2e,0xb9,0xa2,
       0xb1,0x0a,0xa7,0x98,0x4f,0xf8,0xcf,0xcc,0x14,0x25,0x36,0x65,0x78,0xd1,0x38,0xd1,
       0x93,0xd7,0x35,0x70,0x6e,0x96,0x89,0xe1,0xf2,0x59,0x03,0x74,0x07,0x5c,0x3b,0x01,
       0x43,0xcf,0x2a,0x6f,0x0d,0x21,0x08,0xdc,0xc3,0xd6,0x68,0x2c,0x06,0x0e,0x03,0x6c,
       0x39,0x97,0x74,0xa3,0xbc,0x78,0x00,0xc7,0xf3,0x4c,0xba,0x20,0x46,0x93,0xa4,0x28,
       0x03,0xdf,0x65,0x92,0x16,0x5f,0xa1,0x9e,0x34,0xb6,0xc1,0x87,0x2e,0xa1,0x1a,0xa1,
       0x3e,0x7a,0x66,0x48,0xa4,0xf0,0xd5,0x6a,0x5b,0xf4,0x1d,0xff,0xd8,0xf0,0x3a,0xa4 },
      /* Qx */
      {0x00,0x36,0x53,0x88,0xd9,0x58,0x9c,0x18,0xae,0x60,0x81,0x24,0xb4,0xcf,0x74,0x6f,
       0xf4,0x88,0x18,0x3a,0x91,0x2e,0x07,0xd2,0x6b,0x6e,0x86,0x7c,0x5d,0xef,0xb5,0x52,
       0xa5,0xa0,0xdf,0x5a,0x16,0xb6,0x34,0x20,0x14,0xdd,0x1b,0x0b,0x67,0x60,0x07,0x2b,
       0xcd,0x60,0x04,0x5d,0x6a,0x9a,0x51,0x4f,0xc7,0x4d,0x16,0x04,0x7c,0x2e,0x87,0x65,
       0x63,0x6d },
      /* Qy */
      {0x01,0xa5,0x31,0x9b,0x26,0xfd,0x55,0x5f,0x2a,0x12,0xe5,0x57,0x41,0x8f,0x6a,0xa6,
       0x5a,0x34,0x61,0xae,0xae,0xa5,0xc0,0xc6,0xd8,0x69,0x8c,0xea,0xa5,0x49,0x5e,0xed,
       0x7a,0x7d,0x2f,0xed,0x0b,0x76,0xe7,0x7b,0x5b,0xe1,0x18,0x34,0xf3,0x6e,0x41,0x3d,
       0x52,0x88,0xe4,0x72,0x31,0xc0,0xeb,0x0e,0x90,0x07,0xd4,0xb0,0x42,0xbb,0x7a,0x1b,
       0x60,0x14 },
      /* R */
      {0x01,0xd9,0xef,0x37,0x70,0x63,0xa5,0x92,0xcf,0x81,0xe2,0x78,0x15,0xa2,0xc2,0x07,
       0x89,0xff,0x9b,0x60,0xf7,0xf1,0x25,0xe6,0x18,0xb5,0x2d,0x90,0xb3,0x5a,0xbd,0xd4,
       0x1c,0xd7,0xf4,0x37,0xcf,0xad,0x33,0x79,0x53,0xab,0x03,0x14,0xfe,0x8e,0x79,0xa2,
       0xf2,0xd2,0x7f,0xa0,0x85,0x97,0xd4,0xb2,0x83,0x13,0x35,0x8f,0x71,0x4a,0x73,0x73,
       0x21,0xfb },
      /* S */
      {0x00,0xf0,0x1d,0x4f,0x15,0x0e,0x0a,0x17,0x46,0x74,0xa6,0xa6,0x1a,0x58,0xa4,0xba,
       0x78,0x14,0x06,0x02,0x4f,0x6d,0xd1,0xb5,0x25,0x2e,0x04,0x80,0x7b,0x8a,0x80,0x7a,
       0x4f,0xf8,0xd5,0x28,0x83,0xea,0xa2,0x58,0x28,0x6e,0x50,0x6e,0xf4,0xb0,0x4c,0xa8,
       0x90,0xe6,0xf8,0x1a,0x79,0xed,0x9a,0x0c,0xd5,0xed,0x58,0x50,0x94,0xfe,0xa0,0xbc,
       0x5c,0x43 },
      /* Result */
       TEST_PASS
    }, /* previous group sep */

    { /* TV 1-8*/
      C_NIST_P_521, E_SHA512,
      /* Msg */
      {0x22,0x35,0x70,0x5a,0x18,0xad,0x2f,0xc1,0x94,0x0d,0x6f,0x16,0x41,0xef,0x3b,0x70,
       0x19,0xe5,0x6e,0x1c,0xad,0x01,0xaa,0x4c,0x6d,0xa1,0x81,0x50,0xd6,0x22,0x55,0x12,
       0x06,0xdd,0x00,0x16,0x3e,0x71,0xb9,0xc2,0xb1,0x33,0xf2,0x95,0x07,0xfd,0xef,0x14,
       0x4c,0x6f,0xa4,0xa1,0x11,0x0a,0x30,0xeb,0x30,0x9b,0x04,0xb3,0xf3,0xf9,0xd7,0xf5,
       0xd6,0x64,0x9e,0xc3,0xcf,0x94,0x16,0xc8,0x14,0x5e,0x12,0xa0,0x93,0x4d,0xb1,0xe4,
       0x8f,0xf1,0x48,0x00,0xb2,0x38,0xa4,0xab,0xe1,0xe2,0xb9,0x5a,0xe6,0x98,0x4a,0x47,
       0xab,0xa1,0x14,0x08,0xb5,0xf4,0xdb,0xc2,0xcb,0xa8,0x58,0xd5,0x2d,0x58,0x02,0x2b,
       0x66,0xba,0x27,0x21,0x57,0x3b,0x83,0xd5,0xb6,0x2f,0x07,0xf3,0x8c,0x4c,0x58,0xda },
      /* Qx */
      {0x00,0xfd,0x0c,0xac,0x24,0xae,0xb7,0x5c,0xa5,0x0c,0x50,0xa7,0x23,0x40,0x25,0x6b,
       0x43,0x64,0x90,0x50,0xe0,0xfa,0x15,0x5f,0x72,0x34,0x28,0x77,0xbf,0x49,0xc3,0xd5,
       0x7a,0xc2,0xb5,0x1b,0x82,0x83,0x85,0xee,0x6a,0xea,0x94,0xba,0xe3,0x85,0x87,0xe6,
       0x33,0x90,0xf5,0xef,0x4a,0xc5,0x54,0x0a,0x9e,0x6f,0xc6,0xf1,0xc1,0xe7,0x9b,0x52,
       0x46,0x93 },
      /* Qy */
      {0x01,0x07,0xb2,0x27,0xbd,0xd3,0x07,0xef,0xd7,0xa8,0xd4,0x03,0x4f,0x73,0x3d,0x15,
       0x0c,0x41,0x60,0x12,0x15,0xe7,0x6e,0xea,0x2b,0xac,0x62,0xad,0x24,0x27,0xdf,0xf5,
       0x2f,0x75,0xf4,0x6d,0xa3,0xd5,0xfe,0x31,0xbf,0xae,0xdf,0x07,0x1d,0x2a,0x8b,0xb5,
       0xe3,0xc8,0x2b,0xf6,0xc8,0x4e,0xcd,0xf8,0x9c,0xa2,0x33,0xc9,0x2d,0x59,0x9d,0x37,
       0x63,0x09 },
      /* R */
      {0x01,0xc0,0x01,0x96,0xaa,0x5d,0xcb,0xc4,0xc4,0x40,0x4f,0xa7,0x65,0x04,0xa5,0xea,
       0xcb,0xc9,0x6a,0xa6,0x6c,0x3b,0xa5,0x31,0xa3,0xa6,0x79,0xf3,0xfb,0x67,0x5c,0xe5,
       0x8f,0x86,0x3e,0x08,0xb0,0xd2,0xbd,0xea,0xe7,0x4d,0x96,0xad,0x93,0xa3,0x9a,0x78,
       0xed,0x4b,0xb3,0x74,0x9e,0x26,0x56,0x7d,0x0c,0xa5,0xc4,0x8a,0x71,0x07,0x99,0x25,
       0xb6,0x17 },
      /* S */
      {0x00,0xf1,0x18,0x8e,0xba,0x4f,0x09,0x43,0xf4,0x00,0x3d,0xda,0xd6,0xa5,0x46,0x06,
       0xc1,0x3a,0xf2,0x60,0x14,0xdb,0x2e,0xb8,0xe6,0x05,0x34,0xfa,0xd3,0xda,0xe8,0xf0,
       0x7c,0x02,0x1c,0xea,0x09,0x90,0x98,0x7f,0x1e,0x02,0xdc,0xe0,0x3f,0xe5,0x33,0x60,
       0x47,0x2c,0x3d,0xee,0x3c,0x30,0x5b,0xb3,0xef,0x4b,0x0b,0x53,0xea,0x66,0x25,0xbf,
       0x15,0x2a },
      /* Result */
       TEST_FAIL
    }, /* previous group sep */

    { /* TV 1-9*/
      C_NIST_P_521, E_SHA512,
      /* Msg */
      {0xf1,0xf3,0xb2,0x86,0x30,0x75,0x69,0x70,0x45,0x38,0xc9,0x7c,0x68,0x0a,0xbd,0x5b,
       0xb8,0x92,0xb4,0x21,0x46,0x38,0x95,0xc7,0x4a,0xa8,0xe1,0xc4,0xa4,0x62,0x13,0xf2,
       0x1a,0x95,0x94,0x1b,0x86,0x29,0xaf,0x81,0x17,0xc2,0xa0,0x0c,0xbb,0x71,0xf4,0x4d,
       0x79,0x91,0x73,0x57,0xd5,0x29,0xe4,0x86,0xd8,0xd5,0xb8,0x64,0x0f,0x80,0x99,0x60,
       0x97,0x3f,0xe9,0xe2,0x8b,0x34,0xc6,0xe4,0x08,0x2f,0x3b,0x3b,0x06,0x89,0xfd,0x44,
       0xd3,0xaf,0xe5,0xb7,0x1b,0xf4,0x34,0x9d,0x32,0xb7,0xd8,0x0e,0xf5,0xe2,0x2d,0x58,
       0xf1,0x9a,0x13,0x8e,0x1b,0x67,0x6a,0xdd,0xf3,0x84,0xb3,0xe5,0x47,0x95,0xc6,0xce,
       0xe5,0x32,0x64,0xf8,0x83,0xd0,0x80,0x63,0x0b,0xf4,0x8f,0x49,0x87,0x61,0xe6,0xaa },
      /* Qx */
      {0x01,0x04,0xa9,0x6b,0xee,0xa0,0x9d,0x88,0xea,0x67,0x89,0xa9,0x92,0x58,0x80,0xc8,
       0xa9,0xec,0xe8,0xd7,0x64,0xbe,0x93,0x16,0x75,0x64,0x0c,0x1b,0xf8,0x47,0xac,0x8e,
       0x7a,0x8b,0x14,0xf4,0x08,0xba,0x67,0x22,0xc2,0xbf,0x62,0x95,0xdb,0x91,0x32,0xd6,
       0xad,0x2f,0xe2,0x87,0xfa,0x6e,0x68,0x55,0xf7,0xc5,0x8e,0xd2,0x38,0x14,0x8a,0x89,
       0x69,0x44 },
      /* Qy */
      {0x01,0xb5,0xe8,0xe6,0x43,0xfa,0xe5,0x52,0x26,0x14,0x27,0xea,0x7d,0x52,0x1f,0x38,
       0x0a,0xdf,0x60,0x55,0x79,0x46,0x23,0x15,0xc7,0x5e,0x92,0x03,0x20,0x3e,0xbd,0xc9,
       0xee,0x33,0xdd,0x7b,0xa8,0x85,0xb6,0xcc,0xcc,0xcb,0xd2,0x32,0x74,0x62,0x98,0x82,
       0x23,0xc4,0xb3,0x14,0x85,0x31,0x1c,0x93,0x5a,0x34,0x1e,0xe8,0x7b,0xa1,0xee,0x82,
       0x0c,0xe0 },
      /* R */
      {0x00,0xba,0x2c,0x57,0x82,0x7b,0xaa,0xe6,0x84,0xd2,0xc6,0x37,0x59,0x02,0x75,0xc7,
       0x82,0xa6,0xdb,0x26,0x3a,0x53,0x58,0xc8,0xe1,0xa0,0x8b,0x54,0x60,0xca,0x3c,0xf0,
       0xf5,0xff,0x8d,0x41,0x19,0xa6,0xb0,0xd5,0x5f,0xc6,0x8a,0x75,0xc7,0x93,0x09,0x8e,
       0x0a,0x56,0x22,0xa0,0xb4,0xe2,0xfc,0xb0,0xf1,0x79,0x43,0x44,0x01,0x38,0xd7,0x51,
       0x79,0x7b },
      /* S */
      {0x01,0x59,0x4b,0xeb,0x73,0xb2,0xeb,0xb7,0xc5,0x73,0xff,0x07,0xb5,0xc4,0x3e,0x72,
       0x2d,0xc0,0x59,0x79,0xdf,0x0e,0xef,0x53,0x58,0x7e,0x9f,0xe0,0x6a,0x92,0x0f,0x61,
       0xd2,0xef,0xcc,0x76,0x71,0xe6,0xcb,0x87,0x5d,0xf4,0xe4,0xd9,0x2c,0xd4,0xd3,0x7c,
       0xc3,0xea,0xdc,0xb9,0xb6,0xae,0xe8,0xf2,0x09,0x77,0x90,0xce,0x24,0xd6,0xdc,0xda,
       0x87,0x06 },
      /* Result */
       TEST_FAIL
    }, /* previous group sep */

    { /* TV 1-10*/
      C_NIST_P_521, E_SHA512,
      /* Msg */
      {0xb6,0xfd,0x67,0x20,0x65,0x77,0x4d,0x5c,0x25,0x2a,0x6a,0x59,0x6d,0x03,0x73,0xb8,
       0x98,0x46,0x5a,0xf6,0x77,0x8c,0x72,0x19,0x01,0x1d,0xb4,0x82,0xfd,0x94,0xa4,0xe2,
       0x60,0xdf,0x7f,0xb7,0xbd,0x37,0x03,0xda,0x72,0x93,0xe9,0x6e,0x53,0x24,0xc1,0x2f,
       0x5b,0x8e,0x1c,0xd2,0xc2,0x7d,0xc3,0x06,0x20,0x07,0xb6,0xea,0x08,0xe1,0xfc,0xc8,
       0x19,0xca,0x09,0x90,0x33,0xee,0xb0,0xa8,0x8a,0xe2,0x8f,0xe4,0x9b,0xe3,0x30,0xa1,
       0xb7,0x27,0xd4,0x9f,0xbf,0xf8,0xf4,0x97,0xed,0xb4,0x5b,0x8e,0x0f,0xa1,0x55,0x3c,
       0x33,0xe2,0x6f,0xf9,0xb4,0xc3,0x5b,0x72,0x9b,0x85,0xa6,0xe9,0x86,0x54,0xec,0x3f,
       0x46,0xa2,0x08,0x9b,0x6f,0x86,0x30,0x33,0x49,0x8e,0x1e,0x4a,0xac,0x36,0x90,0xf9 },
      /* Qx */
      {0x01,0x0d,0x58,0x7a,0xa8,0x2a,0x4d,0x8e,0x69,0x06,0x72,0xc0,0x0e,0x3f,0xd7,0x18,
       0x26,0xd8,0x92,0x86,0x2d,0x14,0xdc,0x4f,0xba,0xd4,0x93,0x5a,0xaa,0xb8,0x69,0x24,
       0xdc,0x7e,0xe6,0xf7,0xfd,0x3e,0x2b,0xbe,0x86,0xa8,0x65,0x25,0x89,0x44,0x84,0x94,
       0xda,0xb8,0x3d,0x36,0x3d,0x1d,0x62,0x3c,0xba,0xe5,0x9f,0x6c,0x26,0x70,0x70,0x6a,
       0x05,0x76 },
      /* Qy */
      {0x01,0xa9,0x73,0x4c,0x99,0xb6,0xff,0x21,0x26,0x70,0x50,0x73,0x89,0x37,0xc3,0x09,
       0x71,0xd0,0xf6,0xfe,0x07,0xe2,0x97,0x94,0x74,0x8a,0x50,0x17,0xea,0x10,0x36,0xc9,
       0x75,0xc9,0xa5,0x2e,0x6d,0x37,0x39,0xca,0x0e,0x8d,0x70,0xe7,0x84,0x52,0x9c,0xc1,
       0xa7,0x43,0x7a,0xac,0x5d,0x75,0xc6,0x91,0x21,0xb6,0x90,0x20,0xa9,0x53,0x56,0x13,
       0x7f,0x1d },
      /* R */
      {0x01,0x88,0xdc,0xb8,0x40,0xdf,0xc5,0x73,0xa9,0x71,0x17,0x00,0x92,0x26,0xd5,0x8d,
       0xbb,0x93,0x0b,0xa8,0xec,0x84,0x89,0x31,0x78,0x6a,0xbc,0x77,0x06,0x11,0xf3,0x51,
       0x9c,0x8b,0xa7,0x3c,0xce,0xb5,0xb4,0x89,0x17,0x08,0x05,0xbc,0xf0,0x49,0x74,0x67,
       0x2f,0xe6,0x6c,0x90,0x8b,0xa3,0x79,0xac,0xa9,0x9f,0xa6,0x7f,0xec,0x81,0xa9,0x94,
       0xc2,0xd1 },
      /* S */
      {0x00,0x0b,0x1a,0x18,0x55,0x12,0xdc,0x6a,0x65,0xe4,0x54,0xea,0x2b,0xdb,0x80,0x49,
       0xef,0x8f,0x01,0x2a,0x53,0xae,0x87,0xb7,0x59,0xfb,0x5d,0x9e,0xdb,0xa5,0x1e,0xa3,
       0x2e,0x25,0x4e,0x80,0x54,0x5a,0x99,0xeb,0x4b,0x7c,0x58,0xaf,0x96,0xb7,0xc4,0x33,
       0x53,0x5f,0xa3,0xf0,0x09,0xcc,0x64,0x4b,0x1c,0x97,0x66,0x6d,0x88,0x35,0x5a,0xf9,
       0xfc,0x19 },
      /* Result */
       TEST_PASS
    }, /* previous group sep */

    { /* TV 1-11*/
      C_NIST_P_521, E_SHA512,
      /* Msg */
      {0x29,0x76,0x60,0xae,0x8a,0x70,0x38,0x96,0x9a,0x7f,0x08,0x38,0xcd,0x95,0xed,0x18,
       0x85,0xbd,0x20,0xc5,0xa6,0x9a,0x24,0xf5,0xfc,0x8a,0x63,0x91,0x8c,0x21,0x67,0x86,
       0x8a,0xde,0x4e,0x37,0x23,0x90,0xb0,0xc5,0xff,0x19,0x83,0x15,0xca,0x1e,0xf9,0x47,
       0xd9,0xc8,0x50,0x36,0xe3,0x8b,0xa1,0x27,0x7f,0x1e,0x61,0x46,0x72,0x3b,0xd8,0xf9,
       0xad,0x1d,0xb6,0xde,0x80,0xdc,0xe0,0x53,0xc4,0xc9,0xe4,0x59,0x76,0x30,0xa0,0x2d,
       0xc5,0x14,0x68,0x33,0x10,0xd3,0x79,0x2a,0x48,0x31,0xdf,0x7e,0x8f,0xcc,0x77,0x29,
       0x8f,0x2a,0x2f,0xc4,0xc0,0x71,0x41,0x22,0x19,0x48,0x2a,0x6e,0x21,0x8c,0x91,0x67,
       0x19,0xc6,0x13,0xcd,0x24,0x9a,0x33,0x6f,0x82,0x36,0x32,0xae,0xcc,0xff,0x48,0x6f },
      /* Qx */
      {0x01,0x82,0xc9,0x57,0xa6,0x2e,0x2e,0x27,0xaa,0x28,0xac,0xee,0x2e,0x2f,0x7b,0x1e,
       0xd6,0xae,0xf8,0x1c,0x68,0x00,0x1d,0x26,0x48,0xda,0x47,0xd2,0xb6,0x21,0xe8,0xb8,
       0xbd,0x18,0xd9,0x91,0xcd,0x1e,0x3f,0xb9,0xaf,0xb8,0x4f,0x63,0x9f,0xbe,0xd1,0x05,
       0x05,0x84,0x42,0x8c,0xd2,0xa1,0xd5,0x0f,0x87,0x75,0x32,0xff,0xde,0xfd,0xd4,0xe6,
       0xf7,0xba },
      /* Qy */
      {0x00,0x5f,0xad,0xee,0xf5,0x8c,0xc0,0xd7,0x93,0x62,0xb5,0x99,0xe9,0x46,0x36,0xf9,
       0xc7,0x0e,0x3e,0x55,0x80,0xc0,0x85,0xb7,0xea,0x52,0xa5,0xfd,0x24,0xfe,0x4a,0x89,
       0x21,0x20,0xb8,0xf2,0x8b,0xa5,0x3e,0xc2,0x49,0xc4,0x2d,0x6d,0x3b,0x36,0x26,0x8b,
       0x8c,0xa8,0x46,0x4e,0x54,0xb7,0x2d,0x37,0x32,0x7d,0x75,0x04,0xd9,0xb7,0xce,0x53,
       0x4d,0x95 },
      /* R */
      {0x01,0xe3,0xa7,0x8e,0x97,0x3f,0xef,0x6b,0x6d,0xe8,0xa0,0x35,0x64,0x01,0xe8,0x9f,
       0x43,0x5a,0xe5,0xf4,0x9c,0x01,0x73,0xf0,0x73,0xc4,0xdb,0xb9,0xc9,0x14,0x63,0xe4,
       0x20,0xf5,0x26,0x5e,0xad,0xe8,0x30,0x5f,0x11,0xd3,0x0f,0xa8,0xd9,0x7e,0x5b,0x4c,
       0x5a,0xb3,0x39,0x75,0xf7,0x33,0x85,0xae,0xa8,0x1f,0xbd,0xde,0x2f,0x7d,0xdf,0x7f,
       0xdf,0x16 },
      /* S */
      {0x00,0xef,0xec,0xa1,0x0b,0x53,0x62,0xe0,0x5a,0x8f,0x2e,0x3d,0xf6,0x66,0x1d,0x0d,
       0x53,0x6b,0x32,0xca,0x1e,0x0a,0x62,0x51,0x5d,0xf2,0xd9,0x4e,0xb3,0x14,0xaa,0xdb,
       0x5e,0xb4,0x04,0x68,0x48,0x3e,0x24,0xb1,0x6e,0xfe,0x85,0xc5,0x03,0xd6,0xc2,0x31,
       0xef,0x86,0x0a,0xab,0xe6,0x74,0xb7,0x2e,0xd1,0xdd,0xd9,0x38,0x53,0x33,0x8e,0x5e,
       0x4e,0x50 },
      /* Result */
       TEST_FAIL
    }, /* previous group sep */

    { /* TV 1-12*/
      C_NIST_P_521, E_SHA512,
      /* Msg */
      {0x5d,0x05,0x8a,0xe5,0x33,0x53,0x8a,0xd5,0xf6,0x12,0x2e,0x8c,0xc4,0xf5,0xc6,0xdb,
       0xba,0x56,0xc9,0xb9,0xe4,0x9d,0x7e,0xac,0x50,0x68,0x74,0x68,0x3b,0x7b,0x20,0x09,
       0x35,0x52,0xdb,0x5c,0xcd,0x2d,0x81,0x9a,0xd5,0x54,0xea,0xde,0xdb,0x9b,0x2c,0xf6,
       0x13,0xb7,0x34,0x29,0x72,0x3c,0xaa,0x9f,0x21,0xb9,0xfd,0xff,0x20,0xd5,0x75,0xf1,
       0x7b,0x02,0xbb,0xed,0xaa,0x9e,0x2c,0x6b,0x78,0x8e,0xd9,0x0e,0x23,0x9d,0x9d,0xef,
       0x9d,0x10,0x8d,0xf3,0xcc,0x59,0x6f,0xc5,0xe9,0x75,0xc5,0x9f,0x1d,0x78,0xb9,0xbe,
       0x3f,0xa4,0x1c,0x4f,0xe8,0x6d,0x1d,0xca,0xa2,0xd4,0x87,0x6c,0x49,0x4e,0x14,0xbc,
       0x16,0x77,0x36,0xfe,0xf0,0x75,0x63,0xd2,0xdb,0x05,0x06,0xb2,0x4d,0xa8,0x91,0xd1 },
      /* Qx */
      {0x00,0x99,0x11,0xb4,0x1f,0x9a,0xf5,0x25,0xc8,0x74,0xe0,0x5b,0xfd,0xf0,0x50,0x33,
       0x1b,0xf8,0x30,0x29,0x69,0x11,0xbc,0xb1,0x8e,0xec,0x16,0x27,0x50,0x27,0xd6,0x3f,
       0xa1,0x06,0xc8,0x98,0x9b,0x07,0x92,0x1c,0x7e,0x58,0xb0,0x27,0x11,0xb5,0xb5,0x88,
       0x0c,0xc4,0xe6,0xd9,0x17,0x4e,0x0d,0x31,0x06,0x05,0x48,0xcf,0x64,0x3b,0xf7,0xed,
       0x4f,0x0c },
      /* Qy */
      {0x01,0x84,0xfc,0x0f,0xac,0x3c,0x2c,0x80,0xc6,0x9c,0x1c,0x02,0x93,0xf4,0xe5,0xe2,
       0x2f,0xa0,0x8c,0x26,0x7b,0x1f,0x36,0xac,0x5a,0xd6,0xdf,0xdf,0x4d,0xa1,0x75,0x4f,
       0x79,0x42,0xf4,0x8c,0xb5,0x6f,0x56,0xcb,0xa0,0x5e,0x22,0xb9,0x15,0x08,0xfe,0x4d,
       0xb3,0x70,0x30,0x66,0xe8,0xf6,0x97,0xac,0xa5,0x6f,0x97,0x4f,0x3f,0xe5,0x30,0xc9,
       0x64,0x0c },
      /* R */
      {0x01,0x7b,0x8a,0x22,0xfd,0x8f,0x73,0x11,0x23,0x10,0x86,0x79,0x09,0xf2,0x34,0xfa,
       0xd6,0xaa,0x82,0x99,0x9c,0x28,0xea,0x5a,0x2e,0x74,0xb4,0xb4,0xbc,0x79,0xb2,0xf8,
       0x90,0x08,0xb4,0xd3,0x61,0xef,0x7e,0x79,0x7c,0x76,0x56,0xf7,0xd9,0x31,0x7e,0xff,
       0x3e,0x5a,0x49,0x82,0x79,0x9b,0x8c,0xc0,0xdb,0x82,0x61,0x8b,0xd2,0xaa,0x39,0x59,
       0xf6,0x17 },
      /* S */
      {0x01,0xed,0xac,0xc6,0xd1,0xc0,0x00,0x4b,0x20,0x90,0xd2,0x02,0x5d,0x61,0x5d,0xe1,
       0xfd,0x53,0xa9,0x6e,0x82,0x6a,0x39,0x30,0xc7,0xca,0xfa,0xf3,0xc8,0x7f,0x34,0xb2,
       0x58,0x39,0x97,0x53,0x4c,0xfa,0x12,0x74,0x85,0x60,0x0a,0x7a,0xe0,0x4e,0x6a,0xf4,
       0xa2,0xe9,0x8c,0x77,0xfd,0x04,0x50,0x71,0x95,0xe5,0x20,0xe8,0x00,0x14,0xaa,0x98,
       0x2a,0x3c },
      /* Result */
       TEST_FAIL
    }, /* previous group sep */

    { /* TV 1-13*/
      C_NIST_P_521, E_SHA512,
      /* Msg */
      {0xc8,0x05,0xa0,0x7a,0x01,0xe3,0x80,0x6d,0xc8,0x14,0x54,0xee,0x64,0xb3,0xaf,0xb3,
       0x3f,0x30,0x2d,0xbf,0x65,0x06,0x2c,0x1c,0x31,0x16,0x9b,0xb5,0x01,0xff,0xf4,0xc4,
       0xa1,0x90,0x57,0x29,0xa4,0xd0,0xff,0x46,0x3f,0x23,0x49,0xfd,0x74,0x59,0x6b,0x7d,
       0x51,0x41,0x44,0x19,0xe3,0xc9,0x27,0x67,0xeb,0xc9,0xdb,0x52,0xda,0xe4,0xdf,0x2a,
       0x83,0xce,0xe4,0x54,0x86,0xdc,0x12,0x96,0xc6,0x42,0x20,0x00,0x69,0x9c,0x72,0x13,
       0x71,0x78,0xff,0xd6,0x66,0xd2,0xf1,0xd1,0xa1,0x05,0x97,0x2b,0xef,0x6e,0xef,0x74,
       0xe7,0x04,0xd8,0xc8,0x15,0xbe,0xa2,0x69,0x51,0x2a,0x32,0xfb,0x1b,0x8d,0xd8,0x21,
       0x74,0xe0,0x4b,0x2d,0x0d,0x5b,0xea,0xa0,0x40,0x12,0x84,0xa7,0xe2,0xbf,0xac,0xa5 },
      /* Qx */
      {0x00,0x6d,0xa3,0xb6,0x94,0xe3,0x12,0x3e,0xf9,0x6b,0x3f,0xd2,0xab,0x96,0x4f,0x85,
       0xa3,0x61,0x10,0x59,0x07,0x20,0xdc,0x17,0x24,0xa5,0xd5,0x0d,0x30,0x50,0x49,0x89,
       0x57,0x21,0x1c,0x6a,0x15,0x35,0x03,0x2c,0xf1,0xf3,0x12,0x40,0xbf,0xab,0x96,0x7c,
       0xc0,0xcf,0x3b,0x44,0x2c,0x35,0xa1,0xbf,0xa3,0xe7,0x24,0x70,0xdf,0x18,0x63,0xd2,
       0x59,0x3a },
      /* Qy */
      {0x01,0x7d,0x0a,0x5d,0xc4,0x60,0xc8,0x5d,0x03,0x65,0xc7,0xbd,0xc2,0xe9,0x30,0x0e,
       0x27,0x6b,0x8a,0xa9,0x73,0x68,0xaf,0x99,0x72,0x74,0x4f,0x44,0x22,0x44,0x2a,0xfc,
       0x60,0x1e,0xcf,0xe7,0x90,0x3a,0x33,0xb0,0x35,0x4c,0x90,0x1c,0x7b,0x61,0xf2,0x9d,
       0x2d,0x3c,0x56,0x10,0x19,0x2c,0xd1,0x88,0x29,0x1c,0x56,0x51,0x75,0x4b,0x38,0x5b,
       0x87,0xa8 },
      /* R */
      {0x01,0xf9,0xcb,0x1f,0x4e,0x2e,0x65,0x28,0x2a,0x92,0x9a,0xcd,0x8b,0x68,0x5a,0xb3,
       0x4d,0xa1,0x76,0xf5,0xc7,0x3b,0xcb,0x37,0x4f,0xd1,0xb0,0x9b,0xc9,0x95,0x38,0x5c,
       0xe3,0x90,0x2d,0x6c,0x54,0x96,0xb0,0x29,0x16,0xfd,0x5a,0x28,0xf6,0xf8,0xbb,0x66,
       0x28,0x28,0xa7,0x6a,0xa0,0xad,0x14,0xb0,0x1b,0xc2,0x4a,0x63,0xb3,0x28,0xc7,0xbb,
       0x94,0x9b },
      /* S */
      {0x00,0x1d,0x6b,0x3a,0x2f,0x34,0xe3,0xb7,0xbf,0x63,0xd0,0x6b,0x11,0xac,0xe1,0x72,
       0xca,0x61,0xac,0x5a,0x91,0x1a,0x4b,0x40,0x8d,0x76,0x6e,0xb5,0x86,0xc9,0xab,0x82,
       0x0d,0x42,0xf5,0x55,0xe5,0x46,0xd8,0x92,0x64,0x3e,0x12,0xa6,0x75,0x24,0x65,0x42,
       0x7c,0x21,0x3e,0x38,0x39,0xe4,0xf8,0xcb,0x3a,0x7e,0x4f,0xd8,0x36,0x42,0x84,0x3e,
       0x85,0x44 },
      /* Result */
       TEST_FAIL
    }, /* previous group sep */

    { /* TV 1-14*/
      C_NIST_P_521, E_SHA512,
      /* Msg */
      {0x05,0xf1,0xb9,0x75,0xf4,0xf4,0x46,0xa1,0xb8,0xae,0xf5,0x0d,0xfc,0xa6,0x08,0xb0,
       0x35,0x74,0xa8,0x3a,0x7c,0x78,0xd5,0xc2,0xef,0xe1,0x66,0x0a,0x03,0x49,0x94,0x91,
       0x74,0x55,0xb9,0xc8,0xa7,0x74,0xae,0x38,0x1c,0xbf,0xdf,0xff,0x16,0x2d,0x36,0xb9,
       0xa1,0x7b,0xbc,0x6d,0xde,0xf3,0x45,0x17,0xcf,0x8f,0xa5,0x4b,0xb6,0x90,0x1f,0x42,
       0xde,0xf4,0xb7,0x87,0xa8,0x3d,0x32,0x85,0xea,0xf0,0x46,0x21,0xc5,0x82,0x67,0xae,
       0x6d,0x2b,0xdf,0x20,0xb3,0xbb,0x4c,0xb6,0xc4,0xbd,0x8e,0xe5,0x10,0x5e,0xb3,0xf0,
       0x49,0xc4,0x4d,0xf4,0xcc,0xa3,0x9f,0x60,0x15,0xa3,0xd3,0x16,0xf0,0x8a,0xf9,0x7e,
       0xda,0x47,0xf9,0x2a,0x53,0x60,0x0c,0xb2,0x30,0x4a,0x27,0x24,0xe4,0x0a,0x93,0x61 },
      /* Qx */
      {0x00,0xb7,0xe0,0x3f,0x0d,0x62,0x3a,0x09,0x98,0xad,0xd5,0x36,0x0d,0xfb,0x0b,0xfe,
       0x83,0x6f,0xcb,0x0a,0x46,0xb0,0xd6,0xf6,0x97,0xba,0x6b,0x37,0x66,0xbd,0x86,0x98,
       0xac,0x8c,0x7a,0xf6,0x2f,0x50,0x51,0x1c,0x6a,0xa5,0xe6,0x13,0xf4,0xa9,0x9f,0xa2,
       0x8f,0x70,0xb2,0x20,0xba,0x1c,0xdd,0xb2,0x24,0x82,0xbe,0x74,0xc9,0x69,0x95,0x3a,
       0xe6,0xe5 },
      /* Qy */
      {0x00,0xd4,0xee,0x40,0xee,0x44,0x41,0xdc,0x85,0x35,0x67,0x60,0xf8,0x7b,0xa3,0x2e,
       0x2e,0x7c,0x26,0x9a,0x2e,0x53,0xa2,0xe8,0x42,0x5d,0x5f,0xf0,0x2f,0x5e,0x4f,0xe8,
       0xd6,0x5c,0xef,0xe2,0x0e,0x16,0x2c,0x39,0x15,0xd2,0xeb,0x9a,0xd1,0x35,0x4b,0xd2,
       0x85,0x95,0xa8,0x6d,0xbd,0xc9,0x4a,0x5d,0x40,0xc5,0xb4,0x4b,0x1e,0x3a,0xa3,0x96,
       0x54,0x55 },
      /* R */
      {0x01,0xfc,0xba,0x47,0x81,0xde,0x65,0x06,0xf7,0xc3,0xf2,0x65,0x21,0xf0,0xe0,0x36,
       0xb5,0x22,0x5f,0x65,0x1e,0x69,0xe1,0x15,0xd6,0x78,0x4b,0x21,0x76,0xa6,0x66,0xed,
       0xf6,0x9d,0x75,0x96,0x27,0x46,0x84,0x00,0xa7,0x3a,0x13,0x6f,0x59,0x9f,0xb8,0xdb,
       0x46,0x43,0xfc,0xc1,0x6b,0xde,0xee,0xf6,0x38,0x4a,0x18,0x75,0xe1,0xc8,0x1c,0x36,
       0xb9,0x62 },
      /* S */
      {0x00,0xa2,0x1c,0xfa,0xa7,0xe1,0xee,0x0e,0xff,0x7e,0xfc,0x3d,0x7e,0x93,0x63,0x78,
       0x50,0x02,0x83,0xb0,0x06,0x87,0x36,0x30,0x70,0x97,0x44,0x83,0xad,0x47,0x4c,0x58,
       0xc6,0xb5,0x5b,0x77,0xf6,0x78,0xd7,0x8e,0x7c,0xb4,0x4d,0x97,0x45,0xf7,0x93,0x94,
       0x65,0x9b,0xdd,0x26,0xb7,0x26,0x63,0x60,0x83,0x84,0xb5,0xae,0x9c,0xac,0x1c,0x88,
       0x8d,0x13 },
      /* Result */
       TEST_FAIL
    }, /* previous group sep */

    { /* TV 1-15*/
      C_NIST_P_521, E_SHA512,
      /* Msg */
      {0x3a,0x8d,0x80,0x66,0xc0,0xbf,0xc2,0x87,0xe1,0x43,0x4c,0x24,0x30,0x26,0x11,0x10,
       0xe3,0x3d,0x0e,0xbf,0x69,0xd3,0x5b,0x65,0xb0,0xa2,0xd7,0x07,0x63,0xc7,0xfe,0xc9,
       0x93,0xde,0xcf,0x88,0x31,0x74,0xf2,0x16,0xa6,0xc0,0xff,0x62,0x2e,0xf7,0x77,0xc0,
       0x78,0xca,0xe5,0xc6,0x72,0x4f,0x9a,0x02,0x0f,0x8e,0xc0,0x70,0x41,0xdf,0xcc,0xa3,
       0x68,0x9a,0x8a,0xbc,0xce,0x10,0xef,0xae,0x0a,0x2d,0xa9,0x49,0xb8,0x74,0x59,0x58,
       0x6f,0xd0,0x12,0x80,0x5c,0x54,0xf0,0x80,0x7d,0x92,0x7d,0x0b,0x64,0x59,0x5c,0x6b,
       0x18,0x70,0x5b,0x49,0xd4,0x97,0xcc,0x2e,0xe8,0xb8,0x67,0xf9,0xe5,0x8b,0x13,0x82,
       0xe2,0x50,0x65,0x50,0x0d,0x1d,0x74,0x42,0x94,0x42,0x83,0x34,0x66,0x57,0xa8,0x35 },
      /* Qx */
      {0x00,0x1b,0xb7,0xc6,0x23,0xfd,0xe4,0x1b,0xee,0xc7,0xdd,0xfb,0x96,0xf6,0x58,0x48,
       0xc2,0xf5,0x2b,0x50,0xb3,0x95,0x76,0xbf,0x06,0xde,0x6c,0xcf,0x15,0x7b,0x8e,0xc4,
       0x98,0x89,0x52,0x87,0x28,0x48,0x09,0x28,0x23,0x63,0x00,0x44,0x7d,0xa7,0x17,0x1f,
       0x58,0xc8,0xf0,0xe0,0xba,0x8f,0xd3,0xe2,0xcf,0x37,0x8b,0x88,0x61,0x9a,0xa6,0xc1,
       0xe0,0xbc },
      /* Qy */
      {0x01,0xf8,0xb2,0x0a,0x1a,0x7d,0xf3,0x19,0xbf,0x78,0xc2,0xce,0xe0,0x35,0x81,0xa1,
       0xff,0xe8,0xca,0x51,0x07,0xfb,0xfd,0x40,0x76,0x0f,0xbd,0x5e,0xf5,0x24,0x7e,0x2d,
       0xf1,0x09,0x2d,0x5c,0xaf,0x50,0x4a,0x9e,0xe6,0x53,0xde,0xd2,0x99,0x5f,0x0c,0xdd,
       0x84,0x1d,0x6a,0xf2,0x9c,0x9f,0x72,0x07,0x70,0x05,0x6e,0xbb,0xc1,0x28,0x70,0x5f,
       0x68,0xe6 },
      /* R */
      {0x00,0x00,0xdb,0x4c,0x31,0xf3,0x16,0x91,0x22,0x95,0xc5,0xb9,0x50,0x6a,0xab,0xc2,
       0x4b,0x0b,0x2d,0xc2,0xb2,0x35,0x8e,0x6b,0x02,0x31,0x48,0x88,0x9d,0x92,0x00,0xbc,
       0xf4,0x47,0x62,0xe8,0x85,0x75,0xe3,0x59,0xb4,0x86,0x8b,0x2d,0x93,0xba,0x7b,0xdb,
       0x24,0x80,0x0b,0x09,0xfc,0x22,0xea,0xde,0x07,0x44,0xb9,0x83,0x2b,0x71,0xee,0x78,
       0x4e,0x9c },
      /* S */
      {0x01,0x8c,0x84,0x43,0x7f,0xac,0x7c,0xd8,0x20,0x99,0xa2,0xa4,0x23,0x00,0x84,0xac,
       0x27,0xec,0x7e,0xa9,0xc9,0x2e,0x1c,0x9d,0x9a,0x71,0x29,0x0d,0xf9,0xb3,0x7d,0xc8,
       0x81,0xf9,0xba,0x59,0xed,0x33,0x1c,0x22,0xdc,0xa4,0xb2,0xcb,0xb8,0x37,0xcd,0x91,
       0x6e,0x0a,0x78,0x39,0x8d,0x2b,0x7a,0xaf,0x8e,0x88,0xf1,0x13,0xa9,0x42,0xbe,0xac,
       0x48,0xc0 },
      /* Result */
       TEST_FAIL
    }

#endif
};
#endif
