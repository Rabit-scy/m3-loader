/**
 * @file sta_platform.c
 * @brief Platform dedicated functions and utilities used by both xloader and
 * xl_uflasher binaries.
 *
 * Copyright (C) ST-Microelectronics SA 2015
 * @author: APG-MID team
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "shared_data.h"
#include "utils.h"

#include "sta_map.h"
#include "sta_cssmisc.h"
#include "sta_common.h"
#include "sta_platform.h"
#include "sta_ddr.h"

#include "stmpe1600.h"

#include "sta1295_clk.h"
#include "sta1385_clk.h"

#define STMPE1600_I2C_ADDR 0x42

#define ROM_VERSION_ADDR	0x10047FF8
#define ROM_BIST_ADDR		0x10047FFC

/**
 * @brief	Platform early init
 */
int __attribute__((weak)) platform_early_init(struct sta *context)
{
#if defined TRACE_EARLY_BUF
	/* Early trace initialization (in a buffer by default) */
	trace_init(NO_TRACE_PORT, trace_early_buf, sizeof(trace_early_buf));
#else
	trace_init(NO_TRACE_PORT, NULL, 0); /*  No trace */
#endif

	/* Unmask Arasan SDHCI interrupts */
	misc_a7_regs->misc_reg11.bit.sdio_ahb_intr = 1;
	misc_a7_regs->misc_reg11.bit.sdio_ahb_wake_up = 1;
	/* 3.3V supply is selected for SDIO IOs (CLK,CMD, DATA[3:0]) */
	misc_a7_regs->misc_reg3.bit.sdio_voltage_select = 0;
	/* SDIO feedback clock without IO delay */
	misc_a7_regs->misc_reg3.bit.sdio_fbclk_select = 1;

	if (!context)
		return -EINVAL;

	return 0;
}

/**
 * @brief	Identifies the SoC identification and fills the information
 * accordingly.
 * @param	None
 * @return	0 if no error, not 0 otherwise
 */
int m3_get_soc_id(void)
{
	int i;
	struct otp_vr5_reg *p_otp_vr5 =
		(struct otp_vr5_reg *)(&shared_data.otp_regs[5]);
	uint8_t erom_version = (*((int *)ROM_VERSION_ADDR) & 0xFF);

	/* Reset shared data */
	memset(&shared_data, 0, sizeof(shared_data));

	/* Recopy OTP registers at End of AP ESRAM for AP access */
	for (i = 0; i < OTP_SECR_VR_MAX; i++)
		shared_data.otp_regs[i] =
			read_reg(OTP_MISC_M3_BASE + OTP_SECR_VR(i));

	shared_data.erom_version = erom_version;
	shared_data.soc_id = SOC_ID; /* Get SoC ID from compilation flag */

	/* Get SoC cut revision from OTP */
#if SOC_ID != SOCID_STA1385
	/*  Accordo5 SoCs familly */
	switch (shared_data.otp_regs[4]) {
	case 0:
		/* Engeneering sample: default cut1 */
		if (erom_version == 0x30) /* If ROM v3.0 => cut 3 */
			shared_data.cut_rev = CUT_30; /* It's a cut 3 */
		else
			shared_data.cut_rev = CUT_10;
		break;

	case 0x1001: /* This is a STA1295 cut2 ROM 1.0 (not a STA1195) */
		shared_data.cut_rev = CUT_20; /* It's a cut 2 */
		break;

	default: /* OTP programmed */
		/*
		 * On Accordo5 familly: 0 => Cut2.0, 1 => Cut3.0, etc... => +2
		 */
		shared_data.cut_rev = (p_otp_vr5->cut_rev + 2) << 4;
		break;
	}
#else
	/* TC3P SoCs familly */
	switch (erom_version) {
	case 0x10: /* if ROM v1.0 => cut1 */
		shared_data.cut_rev = CUT_10;
		break;

	case 0x20: /* if ROM v2.0 => cut2 (2.0 or 2.1)*/
		shared_data.cut_rev = CUT_20;
		break;

	default: /* Use cut rev field in OTP if any */
		switch (p_otp_vr5->cut_rev) {
		case 0x00:
			shared_data.cut_rev = CUT_10;
			break;

		case 0x06:
			shared_data.cut_rev = CUT_22; /* Cut 2 BF */
			break;

		default:
			shared_data.cut_rev = CUT_UNKNOWN;
			break;
		}
		break;
	}
#endif /* SOC_ID */

	return 0;
}

/**
 * @brief	Identifies the board identification
 * @param	None
 * @return	0 if no error, not 0 otherwise
 */
int m3_get_board_id(void)
{
	uint8_t board_rev_id;
	uint8_t board_id;

	/* Default board and rev */
	board_id = BOARD_ID;
	board_rev_id = 0;
	/* Try to read Board rev ID from STMPE1600 GPIO expander */
	if (!stmpe1600_Init(STMPE1600_I2C_ADDR) &&
	    stmpe1600_ReadID(STMPE1600_I2C_ADDR) == STMPE1600_ID) {
		uint16_t val;

		stmpe1600_IO_InitPin(STMPE1600_I2C_ADDR, STMPE1600_PIN_ALL,
				     STMPE1600_DIRECTION_IN);
		val = stmpe1600_IO_ReadPin(STMPE1600_I2C_ADDR,
					   STMPE1600_PIN_ALL);

		shared_data.board_extensions = val & 0x000F;
		switch ((val & 0x00F0) >> 4)  {
		case 0:
			board_id = BOARD_A5_EVB;
			board_rev_id = 0; /*  revA */
			break;
		case 1:
			board_id = BOARD_A5_EVB;
			board_rev_id = 1; /* revB */
			break;
		case 3:
			board_id = BOARD_TC3_EVB;
			board_rev_id = 1; /* revB (revA doesn't exist) */
			break;
		case 4:
			if (get_soc_id() == SOCID_STA1385) {
				board_id = BOARD_TC3P_CARRIER;
				board_rev_id = 0; /* revA */
			} else {
				board_id = BOARD_A5_EVB;
				board_rev_id = 2; /* revC */
			}
			break;
		case 5:
			board_id = BOARD_A5_EVB;
			board_rev_id = 3; /* revD */
			break;
		case 6:
			board_id = BOARD_TC3_EVB;
			board_rev_id = 2; /* revC */
			break;
		case 7:
			board_id = BOARD_TC3_EVB;
			board_rev_id = 3; /* revD */
			break;
		case 8:
			if (get_soc_id() == SOCID_STA1385) {
				board_id = BOARD_TC3P_MTP;
				board_rev_id = 0; /* revA */
			} else {
				board_id = BOARD_A5_EVB;
				board_rev_id = 4; /* revE */
			}
			break;
		case 9:
			if (get_soc_id() == SOCID_STA1385) {
				board_id = BOARD_TC3P_MTP;
				board_rev_id = 1; /* revB */
			} else {
				board_id = BOARD_TC3_EVB;
				board_rev_id = 4; /* revE */
			}
			break;
		case 10:
			if (get_soc_id() == SOCID_STA1385) {
				board_id = BOARD_TC3P_MTP;
				board_rev_id = 2; /* revC */
			}
			break;
		default:
			/* BOARD_A5_EVB revA */
			break;
		}

		stmpe1600_Exit(STMPE1600_I2C_ADDR);
	}

	shared_data.board_id = board_id;
	shared_data.board_rev_id = board_rev_id;

	return 0;
}

int m3_get_mxtal(void)
{
	switch (get_soc_id()) {
	case SOCID_STA1295:
	case SOCID_STA1275:
	case SOCID_STA1195:
		return(src_m3_regs->resstat.bit_sta1x95.mxtal_fre_sel ?
			   26000000 : 24000000);

	case SOCID_STA1385:
		switch (src_m3_regs->resstat.bit_sta1385.mxtal_fre_sel & 0x3) {
		case 0:
			return 24000000;
		case 1:
			return 26000000;
		case 2:
			return 40000000;
		default:
			return -EINVAL;
		}

	default:
		return -EINVAL;
	}
}

/**
  * @brief  enables used clocks. Actually parses the list of available clocks
  * and enable them if they are used. This allows next boot stages (Linux) to
  * not take care about the unused clocks management.
  *
  * @retval 0 if no error, not 0 otherwise
  */
int sta_enable_clocks(t_src_m3 *src_m3, t_src_a7 *src_a7)
{
	int ret;
	unsigned int i;
	unsigned int nelems_m, nelems_a;
	const struct sta_clk *m, *a;

	switch(get_soc_id()) {
		case SOCID_STA1195:
		case SOCID_STA1295:
		case SOCID_STA1275:
			m = sta1x95_clk_m3;
			nelems_m = NELEMS(sta1x95_clk_m3);
			a = sta1x95_clk_ap;
			nelems_a = NELEMS(sta1x95_clk_ap);
			break;
		case SOCID_STA1385:
			m = sta1385_clk_m3;
			nelems_m = NELEMS(sta1385_clk_m3);
			a = sta1385_clk_ap;
			nelems_a = NELEMS(sta1385_clk_ap);
			break;
		default:
			return -ENODEV;
	}

	for (i = 0; i < nelems_m; i++) {
		ret = srcm3_pclk_change_state(src_m3, m[i].id, m[i].state);
		if (ret)
			goto end;
	}

	for (i = 0; i < nelems_a; i++) {
		ret = srca7_pclk_change_state(src_a7, a[i].id, a[i].state);
		if (ret)
			goto end;
	}

end:
	return ret;
}


