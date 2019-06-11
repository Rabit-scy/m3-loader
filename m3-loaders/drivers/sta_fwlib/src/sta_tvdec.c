/**
 * @file sta_tvdec.c
 * @brief  This file provides all the I2C firmware functions.
 *
 * Copyright (C  ST-Microelectronics SA 2016
 * @author: APG-MID team
 */
#include <string.h>
#include "sta_tvdec.h"
#include "trace.h"
#include "sta_mtu.h"
#include "utils.h"
#include "sta_i2c_service.h"
#include "sta_pinmux.h"
#include "sta_common.h"

t_adv_tab adv7182_cvbs[] = {
	{0x0F, 0x00}, /* Exit Power Down Mode [ADV7182 writes begin] */
	{0x52, 0xCD}, /* SE_CVBS AFE IBIAS */

	/* set input - will be overwritten by "input" parameter */
	{0x00, 0x01}, /* CVBS in on AIN2 */

	/* set standard */
#if (CAM_STANDARD == CAM_NTSC)
	{0x02, 0x50}, /* select NTSC-M */
#elif (CAM_STANDARD == CAM_PAL)
	{0x02, 0x80}, /* select PAL-B/G/H/I/D */
#endif

	/* Circuit Clamp reset */
	{0x0E, 0x80}, /* ADI Required Write */
	{0x9C, 0x00}, /* Reset Current Clamp Circuitry [step1] */
	{0x9C, 0xFF}, /* Reset Current Clamp Circuitry [step2] */
	{0x0E, 0x00}, /* Enter User Sub Map */

	/* Fast switch mode */
	{0x0E, 0x80}, /* ADI Required Write [Fast Switch] */
	{0xD9, 0x44}, /* ADI Required Write [Fast Switch] */
	{0x0E, 0x40}, /* Enter User Sub Map 2 [Fast Switch] */
	{0xE0, 0x01}, /* Enable Fast Switch Mode [Fast Switch] */
	{0x0E, 0x00}, /* Enter User Sub Map */

	/* Adaptive Contrast Enhencement */
	{ 0x0E, 0x40 }, /* Enter User Sub Map 2 */
	{ 0x84, 0x00 }, /* Optimize ACE performance */
	{ 0x80, 0x00 }, /* Enable ACE feature */
	{ 0x0E, 0x00 }, /* Enter User Sub Map */

	/* Select Chroma Shaping Filter Mode */
	{0x17, 0x41}, /* Enable SH1 */

	/* Power-up output pads */
	{0x03, 0x0C}, /* Enable Pixel & Sync output drivers */
	{0x04, 0x87}, /* Power-up INTRQ, HS & VS pads - BT.656-4 mode */
	{0x13, 0x00}, /* Enable ADV7182 for 28_63636MHz crystal */
	{0x1D, 0x40}, /* Enable LLC output driver [ADV7182 writes finished] */
};

struct i2c_com_handler_s	*i2c_h;

int write_adv7181(
		uint8_t reg_addr,
		uint8_t *buf,
		int len)
{
	i2c_set_mcr(I2C_ADV7182_PORT,
		    I2C_MSTMODE_WRITE,
		    I2C_ADV7182_ADDR >> 1,
		    I2C_STARTPROC_DISABLED,
		    I2C_STOPCOND_STOP,
		    len + 1);
	i2c_enable(I2C_ADV7182_PORT);
	i2c_write_fifo(I2C_ADV7182_PORT, &reg_addr, 1);

	i2c_write_fifo(I2C_ADV7182_PORT, buf, len);
	mtu_wait_delay(I2C_ADV7182_READWRITE_DELAY);
	if (i2c_get_controller_status(I2C_ADV7182_PORT) == I2C_CTRLSTATUS_ABORT)
		return -1;

	return 0;
}

int read_adv7181(
		uint8_t reg_addr,
		uint8_t *buf,
		int len)
{
	uint8_t reg = reg_addr;
	int timeout = 500000; /* 500ms */

	i2c_set_mcr(I2C_ADV7182_PORT,
		    I2C_MSTMODE_WRITE,
		    I2C_ADV7182_ADDR >> 1,
		    I2C_STARTPROC_DISABLED,
		    I2C_STOPCOND_REPEATEDSTART, 1);
	i2c_enable(I2C_ADV7182_PORT);
	i2c_write_fifo(I2C_ADV7182_PORT, &reg, 1);

	mtu_wait_delay(I2C_ADV7182_READWRITE_DELAY);
	/* If after timeout, status is abort => exit error */
	if (i2c_get_controller_status(I2C_ADV7182_PORT) == I2C_CTRLSTATUS_ABORT)
		return -1;

	i2c_set_mcr(I2C_ADV7182_PORT,
		    I2C_MSTMODE_READ,
		    I2C_ADV7182_ADDR >> 1,
		    I2C_STARTPROC_DISABLED,
		    I2C_STOPCOND_STOP,
		    1);

	i2c_enable(I2C_ADV7182_PORT);
	/* Loop until all bytes are read */
	while (len > 0 && timeout > 0) {
		int rlen;

		mtu_wait_delay(I2C_ADV7182_READWRITE_DELAY);
		timeout -= I2C_ADV7182_READWRITE_DELAY;
		if (i2c_get_controller_status(I2C_ADV7182_PORT) ==
							I2C_CTRLSTATUS_ABORT)
			return -1;

		rlen = i2c_read_fifo(I2C_ADV7182_PORT, buf, len);
		len -= rlen;
	}

	return 0;
}

void read_status_reg(void)
{
	uint8_t		buf;
	uint32_t	reg[]	= {
		0x01, 0x02, 0x07, 0x10, 0x11, 0x12, 0x13 };
	uint8_t		i;
	portTickType	timeout = 1000;

	for (i = 0; i < (sizeof(reg) / sizeof(uint32_t)); i++) {
		if (i2c_read(i2c_h, reg[i], 1, &buf, 1, &timeout))
			TRACE_ERR("failed to read 0x%X\n", reg[i]);
		TRACE_INFO("reg 0x%X = 0x%X\n", reg[i], buf);
	}
}

/**
 * @brief  Initialize ADV7182
 *
 * @param  op			Sensor Operating Mode(Only CVBS Supported)
 * @return			0 if OK, -1 in case of error.
 */
int init_adv7182(tvdec_op op, uint32_t input, uint32_t *std)
{
	uint32_t			i;
	portTickType			timeout = 1000;
	int ret = -1;

	pinmux_request("adv_mux");

	if (i2c_service_init(I2C_ADV7182_CLOCK)) {
		TRACE_ERR("ADV7182: failed to init I2C\n");
		goto out;
	}

	if (i2c_open_port(I2C_ADV7182_PORT, 0, 0, I2C_BUSCTRLMODE_MASTER)) {
		TRACE_ERR("ADV7182: failed to open I2C\n");
		goto out;
	}
	i2c_set_port_mode(I2C_ADV7182_PORT, I2C_BUSCTRLMODE_MASTER);
	i2c_h = i2c_create_com(I2C_ADV7182_PORT,
			       I2C_FAST_MODE,
			       I2C_ADV7182_ADDR >> 1);

	uint8_t buf;

	if (i2c_read(i2c_h, 0x11, 1, &buf, 1, &timeout)) {
		TRACE_ERR("%s: failed to read at 0x%x\n", __func__, 0x11);
		goto i2c_close;
	}

	TRACE_INFO("ADV7182: IDENT=0x%02X\n", buf);

	switch (op) {
	case CVBS_NTSC:
		for (i = 0; i < sizeof(adv7182_cvbs) / sizeof(t_adv_tab); i++) {
			if (adv7182_cvbs[i].addr == 0x00)
				adv7182_cvbs[i].data = input;

			if (i2c_write(i2c_h,
				      adv7182_cvbs[i].addr,
				      1,
				      &adv7182_cvbs[i].data,
				      1,
				      1,
				      &timeout)) {
				TRACE_ERR("ADV7182: failed to write at 0x%x\n",
					  adv7182_cvbs[i].addr);
				goto i2c_close;
			}
		}
		break;
	default:
		TRACE_ERR("ADV7182 : No such Op Mode : %d\n", op);
	}

#ifdef DEBUG
	mtu_wait_delay(500000);

	if (i2c_read(i2c_h, 0x12, 1, &buf, 1, &timeout)) {
		TRACE_ERR("%s: failed to read at 0x%x\n", __func__, 0x12);
		goto i2c_close;
	}
	TRACE_INFO("ADV7182: Status2: 0x%02X\n", buf);

	if (i2c_read(i2c_h, 0x13, 1, &buf, 1, &timeout)) {
		TRACE_ERR("%s: failed to read at 0x%x\n", __func__, 0x13);
		goto i2c_close;
	}
	TRACE_INFO("ADV7182: Status3: 0x%02X\n", buf);
#endif

#if (CAM_STANDARD == CAM_AUTODETECT)
	mtu_wait_delay(250000); /* wait 250ms*/
	if (i2c_read(i2c_h, ADV7180_REG_STATUS1, 1, &buf, 1, &timeout)) {
		TRACE_ERR("%s: failed to read at 0x%x\n", __func__,
			  ADV7180_REG_STATUS1);
		goto i2c_close;
	}

	switch (buf & ADV7180_STATUS1_AUTOD_MASK) {
	case ADV7180_STATUS1_AUTOD_NTSC_M_J:
	case ADV7180_STATUS1_AUTOD_NTSC_4_43:
		*std = CAM_NTSC;
		break;
	case ADV7180_STATUS1_AUTOD_PAL_B_G:
		*std = CAM_PAL;
		break;
	default:
		*std = 0xFF; /* Unknown standard */
	}
#elif (CAM_STANDARD == CAM_PAL)
	*std = CAM_PAL;
#elif (CAM_STANDARD == CAM_NTSC)
	*std = CAM_NTSC;
#endif

	ret = 0;

i2c_close:
	if (i2c_reset_port(I2C_ADV7182_PORT)) {
		TRACE_ERR("ADV7182: failed to release I2C\n");
		ret = -1;
	}
	TRACE_INFO("ADV7182 : init end\n");
out:
	return ret;
}

/**
 * @brief  Initialize Sensor
 *
 * @param  input		ADV7182 input selected
 * @param  std			ADV7182 detected standard
 * @return			SENSOR_OK on Success
 */
t_sensor_error tv_dec_setup(uint32_t input, uint32_t *std)
{
	int ret = init_adv7182(CVBS_NTSC, input, std);

	if (ret != 0) {
		TRACE_ERR("Failed to initialised Sensor\n");
		return SENSOR_INTERNAL_ERROR;
	}

	TRACE_INFO("Sensor successfully Initialized\n");
	return SENSOR_OK;
}
