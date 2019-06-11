/**
 * @file sta_xloader.c
 * @brief M3 Xloader entry point file
 *
 * Copyright (C) ST-Microelectronics SA 2015
 * @author: APG-MID team
 */

#include <string.h>
#include <errno.h>
#include "trace.h"

#include "utils.h"

#include "FreeRTOS.h"
#include "queue.h"
#include "semphr.h"

#include "sta_type.h"
#include "sta_common.h"
#include "sta_a7.h"
#include "sta_mtu.h"
#include "sta_nic_security.h"
#include "sta_ccc_if.h"
#include "sta_platform.h"
#include "sta_image.h"
#include "sta_pm.h"
#include "sta_ddr.h"
#include "sta_sqi.h"
#include "sta_uart.h"
#include "sta_gpio.h"
#include "sta_pinmux.h"
#include "sta_pmu.h"
#include "CSE_HAL.h"
#include "CSE_ext_manager.h"

#include "sta_cot.h"

#define STMPE1600_I2C_ADDR 0x42

/* M3 context */
static struct sta context;

/*
 * M3 TOC is embedded in M3 xloader in .sysconfig_init section
 * and it's inserted in M3 xloder image by STA flahloader tool
 */
static const struct partition_config_t m3_toc_init
		__attribute__((section(".sysconfig_init")));

/**
 * @brief	Update SoC and board IDs from OTP_VR4 register or from
 *		an autodetection mecanism
 */
static int platform_init(struct sta *context)
{
	int err;

	if (!context)
		return -EINVAL;

	err = m3_get_board_id();
	if (err)
		goto end;

	/* SoC specifities */
	switch (get_soc_id()) {
	case SOCID_STA1295:
	case SOCID_STA1195:
	case SOCID_STA1275:
		context->trace_port = UART3;
		break;
	case SOCID_STA1385:
		context->trace_port = UART2;
		break;
	default:
		break;
	}

#if defined TRACE_EARLY_BUF
	/*
	 * Trace will be initialised later in M3OS,
	 * only initialise UART for next ATF boot stages
	 */
	uart_init(context->trace_port, BR115200BAUD,
			NOPARITY_BIT, ONE_STOPBIT, DATABITS_8);
#else
	m3_init_trace(context);
#endif
end :
	return err;
}

/**
 * @brief	Initializes platform HW interfaces
 * @param	context: xloader application context
 * @return	0 if no error, not 0 otherwise
 */
static int hardware_setup(struct sta *context)
{
	int err;

	/* Identify the SoC at early boot stage to discriminate specific settings */
	m3_get_soc_id();

	err = platform_early_init(context);
	if (err)
		goto end;

	err = m3_lowlevel_core_setup();
	if (err)
		goto end;

#ifdef GPIO_BOOT_MONITORING
	{
		struct gpio_config pin;

		pin.direction = GPIO_DIR_OUTPUT;
		pin.mode = GPIO_MODE_SOFTWARE;
		pin.level	= GPIO_LEVEL_LEAVE_UNCHANGED;
		pin.trig	= GPIO_TRIG_LEAVE_UNCHANGED;
		gpio_set_pin_config(GPIO_BOOT_MONITORING, &pin);
		pmu_free_ao_gpio();
		gpio_set_gpio_pin(GPIO_BOOT_MONITORING);
	}
#endif

	err = m3_core_setup(context);
	if (err)
		goto end;

	TRACE_INFO("Bef sta_ddr_set_retention\n");
	/*
	 * need to maintain retention signal upon out-of-standby as long as
	 * PMU has not set ioctrl_gpioitf bit
	 */
	sta_ddr_pub_set_io_retention(true);
	pmu_free_ao_gpio();

	TRACE_INFO("After sta_ddr_set_retention\n");

	err = platform_init(context);
	if (err)
		goto end;

	TRACE_INFO("After platform_init\n");

	err = m3_boot_dev_setup(context);
	if (err)
		goto end;

	m3_welcome_message(context);

	/* Always divide AP timers clock by 8 */
	a7_timers_clk_set();

	err = sta_ddr_init(pm_suspend_check_resume());
	if (err)
		goto end;

	/*
	 * Init platform security:
	 * Init security driver according to the current SoC.
	 * Ensure the continuity of the Chain of Trust.
	 * Overwrite default non-secure config by the expected security
	 * setting.
	 */
	switch (get_soc_id()) {
	case SOCID_STA1295:
	case SOCID_STA1195:
	case SOCID_STA1275:
#if defined(COT)
		if (get_cut_rev() >= CUT_30) {
			err = ccc_init();
			if (err)
				goto end;
			err = cot_init(context, false);
			if (err)
				goto end;
			ccc_deinit();
		}
#endif
		nic_set_security_cfg();
		break;
	case SOCID_STA1385:
		nic_set_security_cfg();
		if (get_cut_rev() >= CUT_20) {
			err = hsm_init();
			if (err)
				goto end;
			/*
			 * Set the valid external memory ranges for eHSM
			 * interactions:
			 * 2 areas are defined:
			 * - Memory range useable in input and output
			 * - Memory range useable in input only
			 */
			err = CSE_ext_set_valid_ext_mem_range(
					EXT_MEM_RANGE_INOUT_START,
					EXT_MEM_RANGE_INOUT_END,
					EXT_MEM_RANGE_INPUT_START,
					EXT_MEM_RANGE_INPUT_END);
			if (err)
				goto end;

#if defined(COT)
			err = cot_init(context, true);
			if (err)
				goto end;
#endif

#ifdef A7_SHE_REG_MEM_START
			/*
			 * Set emulated register area exposed to A7 core for
			 * eHSM interactions if default config has been
			 * changed.
			 */
			err = CSE_API_ext_set_a7_she_reg_mem_config(
					A7_SHE_REG_MEM_START);
#endif
		}
		break;
	default:
		break;
	}

end :
	if (err)
		TRACE_ERR("%s: failed to init hardware\n", __func__);
	return err;
}


/**
 * @brief	The main entry, responsible for peripherals init and
 *		application
 * @param	none
 * @return	never
 */
int main(void)
{
	int err;
	struct xl1_part_info_t part_info;

	context.bin = BIN_NAME_XL;

	/*
	 * The M3 TOC (.sysconfig_init section) is embedded at start
	 * of M3 XLoader, it must be recopied in .sysconfig (m3_toc)
	 * at definitive place: last 512Bytes of M3 ESRAM to be persistent
	 * for next M3 boot stages
	 */
	m3_toc = m3_toc_init;

	/* Setup all required HW interfaces */
	if (hardware_setup(&context))
		goto exit;

#if defined(EHSM_TEST)
	/*
	 * eHSM test vectors are mapped in .rodata section and
	 * required memory size higher than area available in M3 eSRAM.
	 * So M3 OS is split in 2 parts and .rodata are loaded in DRAM.
	 */
	TRACE_NOTICE("Loading M3 OS part2 image from %s...\n",
		     context.boot_dev_name);
	err = read_image(USER_PART10, &context, NULL, 0);
	if (err)
		goto exit;
#endif

#if defined(ATF)
	m3_set_ap_sync_point(0);
	if (pm_suspend_check_resume()) {
		/*
		 * Restore backup-ed trusted firmware context from DDR
		 * to esram A7.
		 */
		TRACE_NOTICE("Restoring AP ATF from DDR...\n");
		pm_suspend_restore_secure_mem();
	} else {
		/*
		 * Cold boot: First, shadow AP ATF BL1 here,
		 * which shadowes BL2 and finally M3 OS.
		 */
		TRACE_NOTICE("Loading AP ATF BL1 images from %s...\n",
			     context.boot_dev_name);
		err = read_image(AP_XL_ID, &context, &part_info, 0);
		if (err)
			goto exit;
	}
	/* Now start the AP core at given address */
	if (pm_suspend_check_resume())
		a7_start(pm_get_ap_resume_entry());
	else
		a7_start((uint32_t) part_info.entry_address);

#if ! defined(BOOT_M3OS_FROM_M3XL)
	/* Wait M3 OS pen release from ATF BL2 */
	do {
		udelay(100);
		part_info.entry_address = (entry_point_t *)get_m3_pen();
	} while (part_info.entry_address == NULL);

	set_m3_pen(NULL);
#endif /* BOOT_M3OS_FROM_M3XL */
#endif /* ATF */

#if ! defined(ATF) || defined(BOOT_M3OS_FROM_M3XL)
	TRACE_NOTICE("Loading M3 OS images from %s...\n",
		     context.boot_dev_name);
	err = read_image(M3_OS_ID, &context, &part_info, 0);
	if (err)
		goto exit;
#endif
	TRACE_NOTICE("\n");

	/* Jump to M3 entry point */
	part_info.entry_address();
	/* Normaly never returns here */

exit :
	wait_forever;
}

