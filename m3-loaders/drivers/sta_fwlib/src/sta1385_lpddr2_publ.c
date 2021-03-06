/**
 * @file sta1385_lpddr2_pub.c
 * @brief This is the driver for the Synopsys physical utility block (PUB)
 * controller
 *
 * Copyright (C) ST-Microelectronics SA 2015
 * @author: APG-MID team
 */

#include <errno.h>


#include "utils.h"
#include "trace.h"

#include "sta_mtu.h"
#include "sta_gpio.h"
#include "sta_common.h"
#include "sta_ddr.h"
#include "sta1385_lpddr2_setting.h"
#include "sta_pinmux.h"

/* PIR register */
#define PIR_INIT		BIT(0)
#define PIR_DLLSRST		BIT(1)
#define PIR_DLLLOCK		BIT(2)
#define PIR_ZCAL		BIT(3)
#define PIR_DRAMRST		BIT(5)
#define PIR_DRAMINIT	BIT(6)
#define PIR_QSTRN		BIT(7)
#define PIR_RVTRN		BIT(8)
#define PIR_CTLDINIT	BIT(18)
#define PIR_ZCALBYP		BIT(30)
#define PIR_INITBYP		BIT(31)

#define PGSR0_ERR_MASK	0x1F
#define PGSR0_ERR_SHIFT 5

#ifdef USE_BIST
#define BISTRR (0x40 * 4)
#define BISTMSKR0 (0x41 * 4)
#define BISTMSKR1 (0x42 * 4)
#define BISTWCR (0x43 * 4)
#define BISTLSR (0x44 * 4)
#define BISTAR0 (0x45 * 4)
#define BISTAR1 (0x46 * 4)
#define BISTAR2 (0x47 * 4)
#define BISTUDPR (0x48 * 4)
#define BISTGSR (0x49 * 4)
#define BISTWER (0x4a * 4)
#define BISTBER0 (0x4b * 4)
#define BISTBER1 (0x4c * 4)
#define BISTBER2 (0x4d * 4)
#define BISTWCSR (0x4e * 4)
#define BISTFWR0 (0x4f * 4)
#define BISTFWR1 (0x50 * 4)

#define BIST_MAX_LANES 2

#define BIST_DRAM_MODE 0
#define BIST_LOOP_MODE 1

#define BIST_START_COL 0 /* col address, must be BL aligned */
#define BIST_START_ROW 0 /* row address */
#define BIST_START_BANK 0 /* bank address */

#define BIST_START_BANK 0 /* bank address */
#define BIST_RANK1 0

#define BIST_WALKING_BIT0 0
#define BIST_WALKING_BIT1 1
#define BIST_LFSR 2
#define BIST_USER_DEFINED 3

#define BIST_USER_PATTERN 0xA5A5A5A5

#define BIST_WORD_COUNT 0x400 /* words to be generated */

/* constants below are proper to a Micron MT41K256M16 - 32 Meg x 16 x 8 banks */
#define BIST_MCOL (1024 - 8) /* 1K (max - Burst length) */
#define BIST_MROW 32767 /* 32K */
#define BIST_MBANK 7 /* 8 */

/* values to be adapted according to the BIST to be done */

/* Setting this to true will cause BIST never ending */
static bool bist_infinite;

static int bist_mode = BIST_DRAM_MODE;
static int bist_pattern = BIST_LFSR;
static int bist_user_pattern = BIST_USER_PATTERN;
static int bist_wc = BIST_WORD_COUNT;

static void ddr3_bist(uint32_t sc, uint32_t sr, uint32_t sb, uint32_t mc,
		      uint32_t mr, uint32_t mb, uint32_t rk, bool bist_dump)
{
	uint32_t r;
	int l;

	/* Extend the DQS gate for the BIST */
	ddr_write_reg(4, DDR3_PUB_BASE + BISTWCR);

	/* Enable extended gate for BIST */
	r = ddr_read_reg(DDRADDR(PUBL_DSGCR));
	ddr_write_reg(r | (2 << 5), DDRADDR(PUBL_DSGCR));

	/* Enable extended gate for BIST */
	r = ddr_read_reg(DDRADDR(PUBL_DTPR2));
	ddr_write_reg(r | BIT(30), DDRADDR(PUBL_DTPR2));

	/* set the number of patterns to be generated */
	ddr_write_reg(bist_wc, DDR3_PUB_BASE + BISTWCR);

	r = sc | sr << 12 | sb << 28;
	ddr_write_reg(r, DDR3_PUB_BASE + BISTAR0);

	r = rk; /* only on rank 1, address increment is 000 for BL8 */
	if (bist_mode == BIST_DRAM_MODE)
		r |= BIT(7); /* set the BAINC to b1000 */
	ddr_write_reg(r, DDR3_PUB_BASE + BISTAR1);

	/* configure max values */
	r = mc | mr << 12 | mb << 28;
	ddr_write_reg(r, DDR3_PUB_BASE + BISTAR2);

	if (bist_pattern == BIST_USER_DEFINED)
		ddr_write_reg(bist_user_pattern, DDR3_PUB_BASE + BISTUDPR);

	for (l = 0; l < BIST_MAX_LANES; l++) {
		TRACE_NOTICE("%s: BIST (%s) started on lane %d\n", __func__,
			     (bist_mode == BIST_DRAM_MODE ? "DRAM mode" : "Loopback mode"), l);
		/* trigger BIST running */
		r = ddr_read_reg(DDR3_PUB_BASE + BISTRR);
		r = (r & 0xFF81FFF0) | BIT(0) | BIT(1); /* reset BIST */

		if (bist_mode == BIST_DRAM_MODE) {
			r |= BIT(3);
			r |= BIT(14); /* for DatX8 */
		}

		switch (bist_pattern) {
		case BIST_WALKING_BIT0:
			/* do nothing */
			break;
		case BIST_WALKING_BIT1:
			r |= BIT(17);
			break;
		case BIST_USER_DEFINED:
			r |= BIT(17);
			r |= BIT(18);
			break;
		case BIST_LFSR:
		default:
			r |= BIT(18);
			break;
		}

		r |= (l << 19); /* test on current lane */

		if (bist_infinite)
			r |= BIT(4);

		ddr_write_reg(r, DDR3_PUB_BASE + BISTRR);

		/* let some delay to reset BIST */
		mdelay(1);
		r = ddr_read_reg(DDR3_PUB_BASE + BISTRR);
		ddr_write_reg(r & ~BIT(1), DDR3_PUB_BASE + BISTRR); /* set BINST to 01 to start */

		do {
			r = ddr_read_reg(DDR3_PUB_BASE + BISTGSR);
		} while ((r & BIT(0)) != 1);
		TRACE_NOTICE("%s: BIST is over 0x%08x\n", __func__, read_reg(DDR3_PUB_BASE + BISTWER));
		if (bist_dump) {
			TRACE_NOTICE("BISTRR = 0x%08x\n", read_reg(DDR3_PUB_BASE + BISTRR));
			TRACE_NOTICE("BISTWCR = 0x%08x\n", read_reg(DDR3_PUB_BASE + BISTWCR));
			TRACE_NOTICE("BISTMSKR0 = 0x%08x\n", read_reg(DDR3_PUB_BASE + BISTMSKR0));
			TRACE_NOTICE("BISTMSKR1 = 0x%08x\n", read_reg(DDR3_PUB_BASE + BISTMSKR1));
			TRACE_NOTICE("BISTLSR = 0x%08x\n", read_reg(DDR3_PUB_BASE + BISTLSR));
			TRACE_NOTICE("BISTAR0 = 0x%08x\n", read_reg(DDR3_PUB_BASE + BISTAR0));
			TRACE_NOTICE("BISTAR1 = 0x%08x\n", read_reg(DDR3_PUB_BASE + BISTAR1));
			TRACE_NOTICE("BISTAR2 = 0x%08x\n", read_reg(DDR3_PUB_BASE + BISTAR2));
			TRACE_NOTICE("BISTUDPR = 0x%08x\n", read_reg(DDR3_PUB_BASE + BISTUDPR));
			TRACE_NOTICE("BISTGSR = 0x%08x\n", read_reg(DDR3_PUB_BASE + BISTGSR));
			TRACE_NOTICE("BISTWER = 0x%08x\n", read_reg(DDR3_PUB_BASE + BISTWER));
			TRACE_NOTICE("BISTBER0 = 0x%08x\n", read_reg(DDR3_PUB_BASE + BISTBER0));
			TRACE_NOTICE("BISTBER1 = 0x%08x\n", read_reg(DDR3_PUB_BASE + BISTBER1));
			TRACE_NOTICE("BISTBER2 = 0x%08x\n", read_reg(DDR3_PUB_BASE + BISTBER2));
			TRACE_NOTICE("BISTWCSR = 0x%08x\n", read_reg(DDR3_PUB_BASE + BISTWCSR));
			TRACE_NOTICE("BISTWR0 = 0x%08x\n", read_reg(DDR3_PUB_BASE + BISTFWR0));
			TRACE_NOTICE("BISTWR1 = 0x%08x\n", read_reg(DDR3_PUB_BASE + BISTFWR1));
		}
	}

	/* Roll-back to previous state */
	r = ddr_read_reg(DDRADDR(PUBL_DSGCR));
	ddr_write_reg(r & ~(2 >> 5), DDRADDR(PUBL_DSGCR)); /* Disable extended gate for BIST */

	r = ddr_read_reg(DDRADDR(PUBL_DTPR2));
	ddr_write_reg(r & ~BIT(30), DDRADDR(PUBL_DTPR2)); /* Disable extended gate for BIST */
}
#endif /* USE_BIST */

int sta_ddr_pub_do_training(uint32_t mask)
{
	int ret;

	if (mask == PUB_FULL_TRAINING)
		ddr3_pub_do_pir(PIR_QSTRN | PIR_RVTRN | PIR_INIT);
	else
		ddr3_pub_do_pir(mask);

	ret = ddr3_pub_has_errors(PGSR0_ERR_SHIFT, PGSR0_ERR_MASK);
	if (ret) {
		TRACE_ERR("%s: DDR PHY training ended with errors (error mask:0x%x)\n", __func__, ret);
		return ret;
	}

	return ret;
}


int sta_ddr_pub_configure(uint32_t boot_reason)
{
	int ret;

	ddr_write_reg(DDRVAL(PUBL_PGCR), DDRADDR(PUBL_PGCR));
	ddr_write_reg(DDRVAL(PUBL_DX1GCR), DDRADDR(PUBL_DX1GCR));
	ddr_write_reg(DDRVAL(PUBL_DXCCR), DDRADDR(PUBL_DXCCR));
	ddr_write_reg(DDRVAL(PUBL_DCR), DDRADDR(PUBL_DCR));
	/*SK - LPDDR2- S4*/
	ddr_write_reg(DDRVAL(PUBL_PTR0), DDRADDR(PUBL_PTR0));
	ddr_write_reg(DDRVAL(PUBL_MR1), DDRADDR(PUBL_MR1));
	/*400Mhz tWR*/
	ddr_write_reg(DDRVAL(PUBL_MR2), DDRADDR(PUBL_MR2));
	ddr_write_reg(DDRVAL(PUBL_MR3), DDRADDR(PUBL_MR3));
	ddr_write_reg(DDRVAL(PUBL_DTPR0), DDRADDR(PUBL_DTPR0));
	/*400Mhz tRCD6, tWTR3*/
	ddr_write_reg(DDRVAL(PUBL_DTPR1), DDRADDR(PUBL_DTPR1));
	ddr_write_reg(DDRVAL(PUBL_DTPR2), DDRADDR(PUBL_DTPR2));
	/*400Mhz tRFC*/
	ddr_write_reg(DDRVAL(PUBL_DSGCR), DDRADDR(PUBL_DSGCR));
	ddr_write_reg(DDRVAL(PUBL_PTR1), DDRADDR(PUBL_PTR1));
	ddr_write_reg(DDRVAL(PUBL_PTR2), DDRADDR(PUBL_PTR2));

	/* initiate training */
	ret = sta_ddr_pub_do_training(PIR_DRAMRST | PIR_DRAMINIT | PIR_QSTRN | PIR_RVTRN | PIR_INIT);
	if (ret)
		return -EIO;

#if defined(USE_BIST)
		ddr3_bist(BIST_START_COL, BIST_START_ROW, BIST_START_BANK,
			  BIST_MCOL, BIST_MROW, BIST_MBANK, BIST_RANK1, true);
#endif

	return 0;
}

int sta_ddr_pub_set_io_retention(bool set)
{
	return -ENOTSUP;
}

