/**
 * @file shared_data.h
 * @brief Declare variables shared between M3 and AP processors
 *
 * Copyright (C) ST-Microelectronics SA 2015
 * @author: APG-MID team
 */

/*
 * ATTENTION!!!: this file is shared between M3 loaders and AP U-boot
 *               and must be identical
 * - in include/ directory of M3 loaders
 * - in board/st/sta1*xx/ directory of AP U-boot
 */

#ifndef __STA_SHARED_DATA_H__
#define __STA_SHARED_DATA_H__

#if !defined(__ASSEMBLY__) && !defined(ASM)

enum display_configs {
	NO_DETECTION,
	SINGLE_WVGA,
	DUAL_WVGA,
	SINGLE_720P,
	SINGLE_CLUSTER,
	SINGLE_CLUSTER_HD,
	SINGLE_HYBRID_CLUSTER_WVGA,
	SINGLE_HYBRID_CLUSTER_720P,
	SINGLE_720P_10INCHES
};

/* STA SoC identifiers as defined in OTP VR4 register */
#define SOCID_STA1295	0
#define SOCID_STA1195	1
#define SOCID_STA1385	2
#define SOCID_STA1275	3
#define SOCID_MAX	4

/* STA Board identifiers */
#define BOARD_A5_EVB        0
#define BOARD_A5_VAB        1
#define BOARD_TC3_EVB       2
#define BOARD_CR2_VAB       3
#define BOARD_TC3P_CARRIER  4
#define BOARD_TC3P_MTP      5
#define BOARD_UNKNOWN       0xFF

/* STA logical cut versions */
enum STA_CUT_REV {
	CUT_10 = 0x10,
	CUT_20 = 0x20,
	CUT_21 = 0x21,
	CUT_22 = 0x22,
	CUT_23 = 0x23,
	CUT_30 = 0x30,
	CUT_UNKNOWN = 0xFF,
};

enum STA_BOOT_DEV {
	BOOT_NAND = 0,    /* Boot on NAND flash */
	BOOT_MMC = 1,     /* Boot on EMMC or SDCard */
	BOOT_SQI = 2,     /* Boot on Serial NOR flash */
};

/* Copy of corresponding enum t_mmc_card_type defined in sta_sdmmc.h */
enum MMC_CARD_TYPE {
	MMC_CARD_MULTIMEDIA,
	MMC_CARD_MULTIMEDIA_HC,
	MMC_CARD_SECURE_DIGITAL,
	MMC_CARD_SECURE_DIGITAL_IO,
	MMC_CARD_SECURE_DIGITAL_HC,
	MMC_CARD_SECURE_DIGITAL_IO_COMBO
};

struct shared_data_t {
	uint32_t otp_regs[8];
	void *m3_pen;
	uint8_t soc_id;
	uint8_t erom_version;
	uint8_t board_id;
	uint8_t board_rev_id;
	uint8_t board_extensions;
	uint8_t display_cfg;
	uint8_t cut_rev;
	uint8_t padding;
	struct {
		uint32_t base; /* Registers base address */
		uint8_t type;  /* STA_BOOT_DEV */
		uint8_t mmc_num; /* The mmc boot dev number */
		union {
			struct {
				uint16_t flash_id;
				uint16_t jdec_extid;
				uint8_t manuf_id;
			} sqi;
			struct {
				uint32_t ocr;
				uint16_t rca;
				uint8_t csd[16];
				uint8_t bus_width;
				uint8_t card_type; /* Value enum MMC_CARD_TYPE */
			} mmc;
		} dev;
	} boot_dev;
};

#ifndef DECLARE_SHARED_DATA
#define DECLARE_SHARED_DATA extern
#endif
DECLARE_SHARED_DATA struct shared_data_t
	__attribute__((section(".shared_data"))) shared_data;

#ifdef __UBOOT__

/*
 * In U-boot we can't use directly shared_data variable due to relocation
 * We have to pass through gd global data pointer
 */
#include <asm/u-boot.h>		/* boot information for Linux kernel */
#include <asm/global_data.h>	/* global data used for startup functions */
DECLARE_GLOBAL_DATA_PTR;

#ifndef _SHARED_DATA
#define _SHARED_DATA		&(*gd->arch.p_shared_data)
#endif

#else

#ifndef _SHARED_DATA
/*
 * By default, use directly shared_data variable
 * _SHARED_DATA can be defined by specific platform code in order to
 * get shared_data base address according to MMU configuration.
 */
#define _SHARED_DATA		&shared_data
#endif

#endif /* __UBOOT__ */

static inline uint32_t *get_otp_regs(void)
{
	struct shared_data_t *base = _SHARED_DATA;

	return base->otp_regs;
}

static inline uint8_t get_soc_id(void)
{
	struct shared_data_t *base = _SHARED_DATA;

	return base->soc_id;
}

static inline uint8_t get_cut_rev(void)
{
	struct shared_data_t *base = _SHARED_DATA;

	return base->cut_rev;
}

static inline uint8_t get_board_id(void)
{
	struct shared_data_t *base = _SHARED_DATA;

	return base->board_id;
}

static inline uint8_t get_board_rev_id(void)
{
	struct shared_data_t *base = _SHARED_DATA;

	return base->board_rev_id;
}

static inline uint8_t get_board_extensions(void)
{
	struct shared_data_t *base = _SHARED_DATA;

	return base->board_extensions;
}

static inline uint8_t get_erom_version(void)
{
	struct shared_data_t *base = _SHARED_DATA;

	return base->erom_version;
}

static inline uint8_t get_display_cfg(void)
{
	struct shared_data_t *base = _SHARED_DATA;

	return base->display_cfg;
}

static inline void set_display_cfg(uint8_t cfg)
{
	struct shared_data_t *base = _SHARED_DATA;

	base->display_cfg = cfg;
}

static inline void *get_m3_pen(void)
{
	struct shared_data_t *base = _SHARED_DATA;

	return base->m3_pen;
}

static inline void set_m3_pen(void *pen)
{
	struct shared_data_t *base = _SHARED_DATA;

	base->m3_pen = pen;
}

static inline uint8_t get_boot_dev_type(void)
{
	struct shared_data_t *base = _SHARED_DATA;

	return base->boot_dev.type;
}

static inline uint8_t get_mmc_boot_dev(void)
{
	struct shared_data_t *base = _SHARED_DATA;

	return base->boot_dev.mmc_num;
}

static inline uint32_t get_boot_dev_base(void)
{
	struct shared_data_t *base = _SHARED_DATA;

	return base->boot_dev.base;
}

static inline uint8_t get_sqi_manu_id(void)
{
	struct shared_data_t *base = _SHARED_DATA;

	return base->boot_dev.dev.sqi.manuf_id;
}

static inline uint16_t get_sqi_flash_id(void)
{
	struct shared_data_t *base = _SHARED_DATA;

	return base->boot_dev.dev.sqi.flash_id;
}

static inline uint16_t get_sqi_jdec_extid(void)
{
	struct shared_data_t *base = _SHARED_DATA;

	return base->boot_dev.dev.sqi.jdec_extid;
}

static inline uint8_t get_mmc_bus_width(void)
{
	struct shared_data_t *base = _SHARED_DATA;

	return base->boot_dev.dev.mmc.bus_width;
}

static inline uint8_t get_mmc_card_type(void)
{
	struct shared_data_t *base = _SHARED_DATA;

	return base->boot_dev.dev.mmc.card_type;
}

static inline uint8_t *get_mmc_csd(void)
{
	struct shared_data_t *base = _SHARED_DATA;

	return base->boot_dev.dev.mmc.csd;
}

static inline uint32_t get_mmc_ocr(void)
{
	struct shared_data_t *base = _SHARED_DATA;

	return base->boot_dev.dev.mmc.ocr;
}

static inline uint16_t get_mmc_rca(void)
{
	struct shared_data_t *base = _SHARED_DATA;

	return base->boot_dev.dev.mmc.rca;
}

#endif /* __ASSEMBLY__ && ASM */

#endif /* __STA_SHARED_DATA_H__ */
