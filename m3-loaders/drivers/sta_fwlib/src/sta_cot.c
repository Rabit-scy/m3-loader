/**
 * @file sta_cot.c
 * @brief This file provides all the Chain Of Trust functions
 *
 * Copyright (C) ST-Microelectronics SA 2018
 * @author: ADG-MID team
 */
#include <errno.h>
#include "trace.h"
#include "utils.h"
#include "string.h"
#include "sta_mem_map.h"

#include "sta_common.h"
#include "sta_image.h"

#include "CSE_ext_hash.h"
#include "CSE_ext_OTP.h"
#include "CSE_Manager.h"

#include "sta_m3ss_otp.h"
#include "sta_ccc_if.h"

#include "sta_cot.h"

#define EHSM_ROM_FW_ID 0x30
#ifdef COPY_ROTPK_HASH
#define ROTPK_MAGIC_ADDR (void *)(BACKUP_RAM_ATF_ROTPK_HASH_BASE)
#endif

/* Values given by the linker */
extern unsigned int __ap_xl_hash_start__;

static int ehsm_hash_partition(struct xl1_part_info_t *part_info,
			       unsigned char *digest,
			       unsigned int *digest_size)
{
	return CSE_SHA256(part_info->shadow_address, part_info->size, digest,
			  (uint32_t *)digest_size);
}

static int c3_hash_partition(struct xl1_part_info_t *part_info,
			     unsigned char *digest,
			     unsigned int *digest_size)
{
#if !defined(ESRAM_A7_COT_CCC_DATA_BASE)
	return -ENOMEM;
#else
	int err = 0;
	void *ccc_ctx;
	struct ccc_crypto_req req = {0, };

	err = ccc_hash_req_init(&req, HASH_SHA_256_ALG);
	if (err)
		goto end;
	req.hash.digest = (unsigned char *)ESRAM_A7_COT_CCC_DATA_BASE;
#define HASH_SHA_256_SIZE (256 / 8)
	if (digest_size)
		*digest_size = HASH_SHA_256_SIZE;
	ccc_scatter_init(&req.scatter);
	ccc_scatter_append(&req.scatter, part_info->shadow_address,
			   part_info->shadow_address, part_info->size);
	ccc_ctx = ccc_crypto_init(&req);
	if (!ccc_ctx) {
		err = -EINVAL;
		goto end;
	}
	err = ccc_crypto_run(ccc_ctx);
	if (err)
		goto end;
	memcpy(digest, req.hash.digest, HASH_SHA_256_SIZE);
	memset(req.hash.digest, '\0', HASH_SHA_256_SIZE);
end:
	return err;
#endif
}

/**
 * @brief	Init the Chain of Trust
 * @return	0 if no error, not 0 otherwise
 */
int cot_init(struct sta *context, bool ehsm_present)
{
	int err;
	unsigned char digest[CRL_SHA512_SIZE];
	unsigned int digest_size = 0;
	struct xl1_part_info_t part_info;
	enum t_boot_security_level security_level;
#if defined(ATF) && defined(COPY_ROTPK_HASH)
	unsigned int idx;
	unsigned int *reg = (uint32_t *)ROTPK_MAGIC_ADDR;
#endif

	/* Get security level from SAFEMEM */
	if (ehsm_present)
		err = otp_Get_Security_Level(&security_level);
	else
		err = m3ss_otp_get_security_level(&security_level);
	if (err) {
		TRACE_VERBOSE("%s: Read security level fuse fails\n", __func__);
		goto end;
	} else {
		TRACE_VERBOSE("%s: Security Level is %d\n", __func__,
			      security_level);
	}

	if (security_level < BOOT_SECURITY_LEVEL_2)
		TRACE_ERR("%s: CoT requested on non-secure SoC\n", __func__);

	/* Read AP XL image to store AP XL address offset */
	err = read_image(AP_XL_ID, context, &part_info, 0);
	if (err) {
		TRACE_VERBOSE("%s: Read image of AP BLx fails\n", __func__);
		goto end;
	}

	/* Digest computation of AP XL image */
	TRACE_VERBOSE("CoT: Hash computation of AP BLx\n");
	if (!ehsm_present)
		err = c3_hash_partition(&part_info, &digest[0], &digest_size);
	else
		err = ehsm_hash_partition(&part_info, &digest[0], &digest_size);
	if (err) {
		TRACE_VERBOSE("%s: Digest computation of AP BLx fails\n",
			      __func__);
		goto clear;
	}

	/* Compare both digests */
	err = memcmp(&digest[0], (uint8_t *)&__ap_xl_hash_start__,
		     digest_size);
	if (err) {
		TRACE_VERBOSE("%s: Digest verification of AP BLx fails\n",
			      __func__);
		goto clear;
	}

#if defined(ATF) && defined(COPY_ROTPK_HASH)
	/* Read RoTPK Hash from OTP and copy it in xxx */
	for (idx = 64; idx < 72; idx++, reg++) {
		err = otp_Read_Word(idx, reg);
		if (err)
			goto end;
	}
#endif
clear:
	if (err)
		memset(part_info.shadow_address, '\0', part_info.size);
end:
	if (err)
		TRACE_VERBOSE("%s: End with error %d\n", __func__, err);
	return err;
}

