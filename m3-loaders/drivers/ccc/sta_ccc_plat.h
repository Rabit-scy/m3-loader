/**
 * @file sta_ccc_plat.h
 * @brief CCC driver platform configuration header.
 *
 * Copyright (C) ST-Microelectronics SA 2018
 * @author: ADG-MID team
 */

#ifndef _CCC_PLAT_H_
#define _CCC_PLAT_H_

/* These platform configurations might be an argument of ccc_init() func. */
#define C3 0x49000000
#define C3APB4 0x49200000
#define C3_IRQ_ID C3_IRQChannel
#define C3_CLOCK_MAX_FREQ 204800000

/*
 * Controller configuration.
 * Only first dispatcher (0) is available on the platform.
 */
#define NR_DISPATCHERS 1
#define EN_DISPATCHERS 1
#define PROGRAM_SIZE_IN_BYTES 512

/* CCM configuration: allocate the 2 available paths. */
#define MPAES_TO_MOVE_PATH 0
#define MPAES_TO_HASH_PATH 0
#define MOVE_TO_HASH_PATH 1

/* TRNG configuration. */
#define TRNG_INDEX 0
#define TRNG_CLOCK_MIN_FREQ 2000000

/* MPAES configuration. */
#define MPAES_INDEX 1
#define SP_KEY_SLOTS 0x0003
#define GP_KEY_SLOTS 0xfffc
/*
 * Define the maximum data size that can be handled along with MAX_CHUNK_SIZE.
 * Current implementation supports a maximum data size of 512 kB broken down
 * in the following way:
 * - Minimum chunk number is (8 * MAX_CHUNK_SIZE) + 1 = 9
 * - Due to the AES CCM mode, data can be split into header + payload
 *   independently handled. Hereafter is the worst case :
 *   Header ~256 KB requires 6 chunks
 *     |   |
 *     |   | 4 => Size / MAX_CHUNK_SIZE
 *     |---|
 *     |---| 1 => Size mod MAX_CHUNK_SIZE
 *     |---| 1 => (Size mod MAX_CHUNK_SIZE) mod AES_BLOCK_SIZE
 *
 *   Payload ~256 KB requires 6 chunks
 *     |   |
 *     |   | 4 => Size / MAX_CHUNK_SIZE
 *     |---|
 *     |---| 1 => Size mod MAX_CHUNK_SIZE
 *     |---| 1 => (Size mod MAX_CHUNK_SIZE) mod AES_BLOCK_SIZE
 */
#define AES_NR_CHUNKS 12

/* PKA configuration. */
#define PKA_INDEX 2
#define PKA_POWER_ANALYSIS_COUNTERMEASURE AGAINST_DPA
#define RSA_NR_CHUNKS 4
#define ECC_NR_CHUNKS 4

/* MOVE configuration. */
#define MOVE_INDEX 3
#define MOVE_NR_CHUNKS 12

/* UH configuration. */
#define NR_HASH_CHANNEL 1
#define UH_INDEX 4
#define HASH_NR_CHUNKS 12

#define LITTLE_ENDIAN
#undef PREVENT_UNALIGNED_ACCESS
/*
 * Assume that disabling HIF input bytes swapping and performing output
 * swapping by software in case of MOVE and HASH coupling is not required on
 * this platform.
 */
#undef DISABLE_HIF_IF_CH_EN_SWAP
#endif /* _CCC_PLAT_H_ */
