/*
 *  Copyright (C) 2018 STMicroelectronics
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/**
 * @file    loadstore.c
 * @brief	Flash load/store abstraction source file.
 * @details	Set of functions to load and store key image.
 *
 *
 * @addtogroup LOADSTORE
 * @{
 */

#include <string.h>

#include "sta_crc.h"
#include "loadstore.h"

/*===========================================================================*/
/* Module local variables.                                                   */
/*===========================================================================*/
static enum ks_status_t ks_state;
static struct lsblock_t ks_buff;

/**
 * @brief  This routine stores a new blob to the non volatile external device
 * @param  ctx: NVM context
 * @param  addr: address belonging to erasable block
 * @param  payload: pointer to the key storage source buffer
 * @param  size: size of the payload
 * @return 0 if OK else error status
 */
enum RPMx_ErrTy ls_store(t_nvm_ctx *ctx, uint32_t addr,
			 void *payload, uint32_t size)
{
	enum RPMx_ErrTy ret = RPMx_LS_DEVICE_ERR;

	/* Clear the temporary buffer */
	memset((uint8_t *)&ks_buff, 0, sizeof(struct lsblock_t));

	/* Set magic number(s) */
	ks_buff.magic[0] = LS_MAGIC0;
	ks_buff.magic[1] = LS_MAGIC1;
	ks_buff.magic[2] = LS_MAGIC2;
	ks_buff.magic[3] = LS_MAGIC3;

	/* Set the size of the payload */
	ks_buff.size = size;

	/* Copy the payload */
	memcpy(ks_buff.payload, payload, size);

	/* Compute CRC */
	ks_buff.crc = compute_crc32(0, (uint8_t *)&ks_buff,
				    (sizeof(struct lsblock_t) - 4));

#if KS_MEMTYPE == NVM_SQI
	/* Erase the block containing the instance */
	sqi_erase_block(ctx, addr, SQI_64KB_GRANULARITY);
	ret = sqi_write(ctx, addr, (uint32_t *)&ks_buff,
			sizeof(struct lsblock_t));
#elif KS_MEMTYPE == NVM_MMC
	/* Write to SDMMC */
	ret = sdmmc_write(ctx, addr, &ks_buff, sizeof(struct lsblock_t));
#endif
	if (ret < 0)
		ret = RPMx_LS_DEVICE_ERR;
	else
		ret = RPMx_OK;

	return ret;
}

/**
 * @brief  This routine discovers the key storage device
 * @param  ctx: NVM context
 * @param  addr: address of KS in NVM storage
 * @return 0 if OK else error status
 */
enum RPMx_ErrTy ls_discover(t_nvm_ctx *ctx, uint32_t addr)
{
	uint32_t crc;
	int ret = RPMx_LS_DEVICE_ERR;

	/* Clear the temporary key storage buffer */
	memset(&ks_buff, 0, sizeof(struct lsblock_t));

	/* Copy the payload location */
#if KS_MEMTYPE == NVM_SQI
	ret = sqi_read(ctx, addr, &ks_buff, sizeof(struct lsblock_t));
#elif KS_MEMTYPE == NVM_MMC
	ret = sdmmc_read(ctx, addr, &ks_buff, sizeof(struct lsblock_t));
#endif

	if (ret < 0)
		return RPMx_LS_DEVICE_ERR;

	/* Verify if the blob is valid */
	if(ks_buff.size == 0)
		ks_state = KS_NOTVALID;
	else {
		/* Compute the CRC for integrity check */
		crc = compute_crc32(0, (uint8_t *) &ks_buff,
				(sizeof(struct lsblock_t) - 4));

		/* Check CRC */
		if (crc == ks_buff.crc) {
			/* Verify magic number(s) */
			if ((ks_buff.magic[0] != LS_MAGIC0) ||
			(ks_buff.magic[1] != LS_MAGIC1) ||
			(ks_buff.magic[2] != LS_MAGIC2) ||
			(ks_buff.magic[3] != LS_MAGIC3)) {
				ks_state = KS_NOTVALID;
			} else
				ks_state = KS_LOADED;
		} else
			/* CRC is not correct */
			ks_state = KS_NOTVALID;
	}

	return RPMx_LS_DEVICE_INIT;
}

/**
 * @brief  This routine copies the latest valid instance
 *         to the destination payload buffer
 * @param  ctx: NVM context
 * @param  payload: pointer to the key storage destination buffer
 * @param  size: payload size
 * @return 0 if OK else error status
 */
enum RPMx_ErrTy ls_load(t_nvm_ctx *ctx, uint32_t addr,
			void *payload, uint32_t size)
{
	enum RPMx_ErrTy ret = RPMx_OK;

	if (ks_state == KS_LOADED) {
		/* Verify the payload size */
		if (ks_buff.size == size)
			/* Copy the latest valid instance */
			memcpy(payload, ks_buff.payload, size);
		else
			/* Size error */
			ret = RPMx_LS_DEVICE_ERR;
	} else if (ks_state == KS_NOTVALID)
		ret = RPMx_LS_DEVICE_ERR;
	else
		ret = RPMx_LS_DEVICE_FAILURE;

	return ret;
}

/**
 * @brief  This routine erase the latest valid instance
 * @param  ctx: NVM context
 * @param  addr: NVM address to clean
 * @return 0 if OK else error status
 */
enum RPMx_ErrTy ls_erase(t_nvm_ctx *ctx, uint32_t addr)
{
	enum RPMx_ErrTy ret = RPMx_LS_DEVICE_ERR;

#if KS_MEMTYPE == NVM_SQI
	/* Erase the block containing the instance */
	ret = sqi_erase_block(ctx, addr, SQI_64KB_GRANULARITY);
#elif KS_MEMTYPE == NVM_MMC
	/* Clear the temporary buffer */
	memset((uint8_t *)&ks_buff, 0, sizeof(struct lsblock_t));
	/* Write null data to SDMMC */
	ret = sdmmc_write(ctx, addr, &ks_buff, sizeof(struct lsblock_t));
#endif
	if (ret < 0)
		ret = RPMx_LS_DEVICE_ERR;
	else
		ret = RPMx_OK;

	return ret;
}

/**
 * @brief  This routine turns off the key storage framework
 * @param  ctx: NVM context
 * @return : None
 */
void ls_deinit(t_nvm_ctx *ctx)
{
	/* Deinit the device */
	return;
}

/** @} */
