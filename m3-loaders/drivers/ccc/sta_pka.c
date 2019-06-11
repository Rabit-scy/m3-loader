/**
 * @file sta_pka.c
 * @brief CCC PKA channel driver.
 *
 * Copyright (C) ST-Microelectronics SA 2018
 * @author: ADG-MID team
 */

#include <errno.h>
#include <stdarg.h>
#include <string.h>

#include "sta_ccc_plat.h"
#include "sta_ccc_osal.h"
#include "sta_ccc_if.h"
#include "sta_ccc.h"
#include "sta_pka.h"

#define PREFIX DEV_NAME ": "

static struct pka_context ctx = {{0}, };

struct pka_data {
	const int *ids;
	const unsigned int nr_id;
};

/* List all ids compatible with this driver. */
static const int ids[] = {0x00006009, 0x0000600b, 0x0000600c};

static struct pka_data pka_data = {.ids = &ids[0],
				   .nr_id = ARRAY_SIZE(ids)};

#define LOG2_8 3
#define LOG2_8_MASK (8 - 1)
inline unsigned int size_in_bytes(unsigned int size_in_bits)
{
	unsigned int nr = size_in_bits >> LOG2_8;
	unsigned int remainder = size_in_bits & LOG2_8_MASK;

	if (remainder)
		nr++;

	return nr;
}

unsigned int get_dimension(unsigned char *bytes,
			   unsigned int nr_bytes)
{
	unsigned int i, nr;

	/* Assume that input number is big-endian. */
	for (i = 0; i < nr_bytes; i++) {
		nr = get_byte_dimension(*bytes);
		if (nr)
			return nr + (nr_bytes - (i + 1)) * 8;
		bytes++;
	}

	return 0;
}

inline unsigned char *word_padd(unsigned char *bignum, unsigned int size)
{
	unsigned int remainder, padding = 0;

	remainder = size % sizeof(unsigned int);
	if (remainder) {
		padding = sizeof(unsigned int) - remainder;
		memset(bignum, '\0', padding);
	}
	return bignum + padding;
}

/*
 * Append to a big number another one padded with leading zeroes up to an
 * integer number of words.
 *
 * buf is the destination buffer
 * bignum is the number to be appended including possible leading zeroes
 * size is the allocated size in bytes of the number to be appended
 *
 * If *actual_size is not zero, it handles the size set by caller. In this case
 * the big number size in bits is not prepended.
 * If *actual_size is zero, it will report to caller the computed size of the
 * copied number.
 *
 */
int append_bignum(unsigned char **buf, unsigned char *bignum,
		  unsigned int size, unsigned int *actual_size)
{
	unsigned int nr_zeros;

	if (!actual_size)
		return -EINVAL;

	if (!*actual_size) {
		unsigned int nr_bits = get_dimension(bignum, size);

		/* Compute actual size. */
		*actual_size = size_in_bytes(nr_bits);
		if (!*actual_size)
			return -EINVAL;
		memcpy(*buf, (unsigned char *)&(nr_bits), sizeof(nr_bits));
		swap_bytes_if(*buf, sizeof(nr_bits));
		*buf += sizeof(nr_bits);
	}

	*buf = word_padd(*buf, *actual_size);
	nr_zeros = size - *actual_size;

	memcpy(*buf, bignum + nr_zeros, *actual_size);
	*buf += *actual_size;

	return 0;
}

struct ccc_channel *pka_get_channel(void *arg)
{
	if (arg)
		return &((struct pka_context *)arg)->channel;

	return NULL;
}

#define NONE PK_NONE_ALG
#define RSA PK_RSA_ALG
#define ECC PK_ECC_ALG
#define ECDSA PK_ECDSA_ALG
static struct pka_alg *check_alg(struct ccc_crypto_req *req)
{
	switch (req->asym.alg) {
	case RSA:
		return &pka_rsa_alg;
	case ECC:
		return &pka_ecc_alg;
	case ECDSA:
		return &pka_ecdsa_alg;
	default:
		TRACE_INFO(PREFIX "Unhandled algorithm\n");
		break;
	}

	return NULL;
}

void *pka_crypto_init(struct ccc_crypto_req *req,
		      struct ccc_dispatcher *dispatcher)
{
	struct pka_context *context = &ctx;

	context->dispatcher = dispatcher;
	context->alg = check_alg(req);
	if (!context->alg)
		return NULL;

	struct pka_alg *alg = context->alg;

	if (!alg->crypto_init)
		return NULL;
	return alg->crypto_init(req, context);
}

struct operation get_opcode(int index, unsigned char code,
			    unsigned int nr_param, ...)
{
	struct operation op;
	va_list params;

	switch (code) {
	case MONTY_PAR:
		ASSERT(nr_param == 1);
		op.code = code << OP_ID_SHIFT;
		op.wn = 2;
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

int pka_program_prolog(void *arg)
{
	struct pka_context *context = (struct pka_context *)arg;
	struct pka_alg *alg = context->alg;

	if (alg->program_prolog)
		alg->program_prolog(context);

	return 0;

}

int pka_program(void *arg)
{
	struct pka_context *context = (struct pka_context *)arg;
	struct pka_alg *alg = context->alg;

	if (!alg->program)
		return -EFAULT;

	alg->program(context);

	return 0;
}

int pka_program_epilog(void *arg)
{
	struct pka_context *context = (struct pka_context *)arg;
	struct pka_alg *alg = context->alg;

	if (alg->program_epilog)
		alg->program_epilog(context);

	return 0;
}

int pka_post_processing(void *arg)
{
	struct pka_context *context = (struct pka_context *)arg;
	struct pka_alg *alg = context->alg;

	if (alg->post_process)
		return alg->post_process(context);

	return 0;
}

static inline struct pka_data *get_engine_data(__maybe_unused int id)
{
	return &pka_data;
}

int pka_init(struct ccc_controller *c3, int index)
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

	channel->error_mask = BERR | DERR | PERR | IERR | AERR | OERR;
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
