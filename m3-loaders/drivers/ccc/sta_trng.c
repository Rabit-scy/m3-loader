/**
 * @file sta_trng.c
 * @brief CCC TRNG channel driver.
 *
 * Copyright (C) ST-Microelectronics SA 2018
 * @author: ADG-MID team
 */

#include <errno.h>
#include <stdarg.h>

#include "sta_ccc_plat.h"
#include "sta_ccc_osal.h"
#include "sta_ccc_if.h"
#include "sta_ccc.h"

#define DEV_NAME "trng"
#define PREFIX DEV_NAME ": "

struct trng_context {
	struct ccc_channel channel;
	struct ccc_dispatcher *dispatcher;
	struct ccc_dma random;
};

static struct trng_context ctx = {{0},};

struct trng_data {
	const int *ids;
	const unsigned int nr_id;
};

/* List all ids compatible with this driver. */
static const int ids[] = {0x0000f806, 0x0000f807, 0x0000f808};

static struct trng_data trng_data = {.ids = &ids[0],
				     .nr_id = ARRAY_SIZE(ids)};

struct ccc_channel *trng_get_channel(void *arg)
{
	if (arg)
		return &((struct trng_context *)arg)->channel;

	return NULL;
}

#define TRNG_CSCR 0x018
#define DMA_REG (1 << 31)
static inline void set_reg_mode(struct trng_context *context)
{
	struct ccc_channel *channel = &context->channel;
	unsigned int status;

	status = read_reg(channel->base + TRNG_CSCR);
	status |= DMA_REG;
	write_reg(status, channel->base + TRNG_CSCR);
}

static inline void set_dma_mode(struct trng_context *context)
{
	struct ccc_channel *channel = &context->channel;
	unsigned int status;

	status = read_reg(channel->base + TRNG_CSCR);
	status &= ~DMA_REG;
	write_reg(status, channel->base + TRNG_CSCR);
}

void *trng_crypto_init(struct ccc_crypto_req *req,
		       struct ccc_dispatcher *dispatcher)
{
	struct trng_context *context = &ctx;

	context->dispatcher = dispatcher;

	if (req->scatter.nr_entries > 1) {
		TRACE_INFO(PREFIX "Scattered output not handled\n");
		return NULL;
	}
	if (!is_dst_32bits_aligned(&req->scatter)) {
		TRACE_INFO(PREFIX "Output not aligned on 32bits\n");
		return NULL;
	}
	context->random.addr = req->scatter.entries[0].dst;
	if (req->scatter.nr_bytes == 0) {
		TRACE_INFO(PREFIX "No data to produce\n");
		return NULL;
	}
	if (!is_size_32bits_aligned(&req->scatter)) {
		TRACE_INFO(PREFIX "Data size not multiple of 4B\n");
		return NULL;
	}
	context->random.size = req->scatter.nr_bytes;

	set_dma_mode(context);

	return context;
}

#define OP_ID_SHIFT 22
#define ENABLE 0xa
#define DISABLE 0xb
#define GET_VALUE 0x18
#define LENGTH_SHIFT 0
static struct operation trng_get_opcode(int index, unsigned char code,
					unsigned int nr_param, ...)
{
	struct operation op;
	va_list params;

	switch (code) {
	case ENABLE:
		ASSERT(nr_param == 0);
		op.code = code << OP_ID_SHIFT;
		op.wn = 0;
		break;
	case DISABLE:
		ASSERT(nr_param == 0);
		op.code = code << OP_ID_SHIFT;
		op.wn = 0;
		break;
	case GET_VALUE:
		ASSERT(nr_param == 1);
		op.code = code << OP_ID_SHIFT;
		op.wn = 1;
		va_start(params, nr_param);
		op.code |= va_arg(params, unsigned int) << LENGTH_SHIFT;
		va_end(params);
		break;
	default:
		ASSERT(0);
		op.wn = 0;
		break;
	}
	op.code |= (index << CHN_SHIFT);

	return op;
}

int trng_program_prolog(void *arg)
{
	struct trng_context *context = (struct trng_context *)arg;
	struct ccc_channel *channel = &context->channel;
	struct ccc_dispatcher *dispatcher = context->dispatcher;
	struct operation op;

	op = trng_get_opcode(channel->index, DISABLE, 0);
	ccc_program(dispatcher, op.code, op.wn);
	/*
	 * Wait as long as the low frequency domain of TRNG core can see the
	 * disable/enable sequence.
	 */
#define WAIT_CYCLES (1 + C3_CLOCK_MAX_FREQ / TRNG_CLOCK_MIN_FREQ)
	ASSERT(WAIT_CYCLES <= UINT16_MAX);
	op = ccc_get_wait_opcode(WAIT_CYCLES);
	ccc_program(dispatcher, op.code, op.wn);
	op = trng_get_opcode(channel->index, ENABLE, 0);
	ccc_program(dispatcher, op.code, op.wn);

	return 0;
}

int trng_program(void *arg)
{
	struct trng_context *context = (struct trng_context *)arg;
	struct ccc_channel *channel = &context->channel;
	struct ccc_dispatcher *dispatcher = context->dispatcher;
	struct operation op;

	op = trng_get_opcode(channel->index, GET_VALUE, 1,
			     context->random.size);
	ccc_program(dispatcher, op.code, op.wn, context->random.addr);

	return 0;
}

int trng_program_epilog(void *arg)
{
	struct trng_context *context = (struct trng_context *)arg;
	struct ccc_channel *channel = &context->channel;
	struct ccc_dispatcher *dispatcher = context->dispatcher;
	struct operation op;

	op = trng_get_opcode(channel->index, DISABLE, 0);
	ccc_program(dispatcher, op.code, op.wn);

	return 0;
}

static inline struct trng_data *get_engine_data(__maybe_unused int id)
{
	return &trng_data;
}

int trng_init(struct ccc_controller *c3, int index)
{
	struct ccc_channel *channel = &ctx.channel;
#ifdef DEBUG
	unsigned int scr;
#endif

	channel->controller = c3;
	channel->index = index;
	channel->base = ccc_get_ch_physbase(c3, channel->index);

	channel->id = ccc_get_ch_id(channel->base);
	if (channel->id == 0) {
		TRACE_ERR(PREFIX "Unused channel\n");
		return -ENODEV;
	}
	TRACE_INFO(PREFIX "Channel identifier: %08x\n", channel->id);
	/*
	 * Driving an unknown version of the channel may lead to an
	 * unpredictable behaviour.
	 */
	if (!ccc_is_channel_supported(channel->id, ids, ARRAY_SIZE(ids)))
		TRACE_ERR(PREFIX "Bad channel identifier: %x\n", channel->id);

	if (!ccc_is_channel_present(channel)) {
		TRACE_ERR(PREFIX
			  "Channel %d does not exist\n", channel->index);
		return -EINVAL;
	}

	channel->error_mask = BERR | DERR | IERR | AERR | OERR;
	ccc_set_channel_name(channel, DEV_NAME);

	ccc_set_channel_data(channel, get_engine_data(channel->id));

#ifdef DEBUG
	scr = ccc_read_channel_scr(channel);
	TRACE_INFO(PREFIX "Endianness: %s\n",
		   ccc_get_channel_scr_endian(scr) ?
		   "little/swap" : "big/no swap");
#endif

	return 0;
}
