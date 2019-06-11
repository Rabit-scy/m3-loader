/**
 * @file sta_hash.c
 * @brief CCC HASH channel driver.
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

#define DEV_NAME "hash"
#define PREFIX DEV_NAME ": "

struct hash_context {
	bool inited;
	struct ccc_channel channel;
	struct ccc_dispatcher *dispatcher;
	unsigned int alg;
	bool move, cipher_sym;
	struct ccc_chunk chunks[HASH_NR_CHUNKS];
	unsigned int nr_chunks;
	unsigned char *digest;
};

static struct hash_context ctx[NR_HASH_CHANNEL] = {{0,} };

struct hash_data {
	const unsigned int version;
	const int *ids;
	const unsigned int nr_id;
	const int *algs;
	const unsigned int nr_alg;
	const bool digest_truncation;
};

/* List all ids compatible with this driver. */
static const int ids[] = {0x00004016, 0x00004017, 0x00011004};

/* List ids compatible with and algs supported by UH driver. */
static const int uh_ids[] = {0x00004016, 0x00004017};
static const int uh_algs[] = {HASH_MD5_ALG, HASH_SHA_1_ALG, HASH_SHA_256_ALG,
			      HASH_SHA_224_ALG};

static struct hash_data uh_data = {.version = UH_VERSION,
				   .ids = &uh_ids[0],
				   .nr_id = ARRAY_SIZE(uh_ids),
				   .algs = &uh_algs[0],
				   .nr_alg = ARRAY_SIZE(uh_algs),
				   .digest_truncation = true};

/* List ids compatible with and algs supported by UH2 driver. */
static const int uh2_ids[] = {0x00011004};
static const int uh2_algs[] = {HASH_SHA_384_ALG, HASH_SHA_512_ALG};

static struct hash_data uh2_data = {.version = UH2_VERSION,
				    .ids = &uh2_ids[0],
				    .nr_id = ARRAY_SIZE(uh2_ids),
				    .algs = &uh2_algs[0],
				    .nr_alg = ARRAY_SIZE(uh2_algs),
				    .digest_truncation = false};

struct ccc_channel *hash_get_channel(void *arg)
{
	if (arg)
		return &((struct hash_context *)arg)->channel;

	return NULL;
}

bool hash_is_alg_supported(unsigned int alg)
{
	switch (alg) {
	case HASH_MD5_ALG:
	case HASH_SHA_1_ALG:
	case HASH_SHA_256_ALG:
	case HASH_SHA_224_ALG:
	case HASH_SHA_384_ALG:
	case HASH_SHA_512_ALG:
		break;
	default:
		return false;
		break;
	}
	return true;
}

#define TO_ALG_BITS(a) (HASH_ALG_SHIFTED_MASK & (a))
static inline int get_alg_code(struct ccc_crypto_req *req)
{
	if (hash_is_alg_supported(req->hash.alg))
		return TO_ALG_BITS(req->hash.alg);
	ASSERT(0);

	/* Can't be reached. */
	return HASH_NONE_ALG;
}

static inline bool is_alg_supported(int alg, struct hash_data *hash_data)
{
	unsigned int i;

	if (!hash_data)
		return false;
	for (i = hash_data->nr_alg; i--;)
		if (alg == hash_data->algs[i])
			return true;
	return false;
}

static inline struct hash_context *get_context_from_alg(int alg)
{
	unsigned int i = ARRAY_SIZE(ctx) - 1;
	struct hash_data *data;

	do {
		if (ctx[i].inited) {
			data = ccc_get_channel_data(&ctx[i].channel);
			if (is_alg_supported(alg, data))
				return &ctx[i];
		}
	} while (i--);
	return NULL;
}

void *hash_crypto_init(struct ccc_crypto_req *req,
		       struct ccc_dispatcher *dispatcher)
{
	struct hash_context *context = get_context_from_alg(req->hash.alg);

	if (!context) {
		TRACE_INFO(PREFIX "Hash algorithm is not supported\n");
		return NULL;
	}
	context->dispatcher = dispatcher;
	context->alg = get_alg_code(req);
	context->cipher_sym = (AES_NONE_ALG != req->sym.alg);
	context->move = !is_in_place(&req->scatter);

	/* Assume that zero address is not valid on the platform. */
	if (NULL == req->hash.digest) {
		TRACE_INFO(PREFIX "Hash pointer is likely not set\n");
		return NULL;
	}

	if (context->move || context->cipher_sym) {
		/*
		 * HASH input is plugged on another channel output likely MOVE
		 * or MPAES.
		 */
		context->nr_chunks = 0;
	} else {
		/* HASH input is in memory. */
		if (req->scatter.nr_bytes == 0) {
			TRACE_INFO(PREFIX "No data to compute\n");
			return NULL;
		}
		context->nr_chunks = HASH_NR_CHUNKS;
		if (!ccc_prepare_chunks(&(context->chunks[0]), NULL,
					req, &context->nr_chunks))
			return NULL;
	}

	context->digest = req->hash.digest;

	return context;
}

#define OP_ID_SHIFT 20
#define INIT 0
#define ALG_SHIFT 23
#define INIT_CUSTOM_IV 0x41
#define APPEND 0x42
#define LENGTH_SHIFT 0
#define END 0x44
#define T_SHIFT 20
static struct operation hash_get_opcode(int index, unsigned char code,
					unsigned int nr_param, ...)
{
	struct operation op;
	va_list params;

	switch (code) {
	case INIT:
		ASSERT(nr_param == 1);
		op.code = code << OP_ID_SHIFT;
		op.wn = 0;
		va_start(params, nr_param);
		op.code |= va_arg(params, unsigned int) << ALG_SHIFT;
		va_end(params);
		break;
	case APPEND:
		ASSERT(nr_param == 2);
		op.code = code << OP_ID_SHIFT;
		op.wn = 1;
		va_start(params, nr_param);
		op.code |= va_arg(params, unsigned int) << ALG_SHIFT;
		op.code |= va_arg(params, unsigned int) << LENGTH_SHIFT;
		va_end(params);
		break;
	case END:
		ASSERT(nr_param == 2);
		op.code = code << OP_ID_SHIFT;
		op.wn = 1;
		va_start(params, nr_param);
		op.code |= va_arg(params, unsigned int) << ALG_SHIFT;
		op.code |= va_arg(params, unsigned int) << T_SHIFT;
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

int hash_program_prolog(void *arg)
{
	struct hash_context *context = (struct hash_context *)arg;
	struct ccc_channel *channel = &context->channel;
	struct ccc_dispatcher *dispatcher = context->dispatcher;
	struct operation op;

	op = hash_get_opcode(channel->index, INIT, 1,
			     context->alg);
	ccc_program(dispatcher, op.code, op.wn);

	/* If requested, custom IV programmation should be inserted here. */

	return 0;
}

int hash_program(void *arg)
{
	struct hash_context *context = (struct hash_context *)arg;
	struct ccc_channel *channel = &context->channel;
	struct ccc_dispatcher *dispatcher = context->dispatcher;
	struct ccc_chunk *chunk = &(context->chunks[0]);
	struct operation op;
	unsigned int i;

	for (i = 0; i < context->nr_chunks; i++) {
		op = hash_get_opcode(channel->index, APPEND, 2,
				     context->alg,
				     chunk->in.size);
		ccc_program(dispatcher, op.code, op.wn, chunk->in.addr);
		chunk++;
	}

	return 0;
}

static inline bool is_digest_truncation_supported(struct hash_data *hash_data)
{
	return hash_data->digest_truncation;
}

#define T_RESET 0
#define FULL 0
#define TRUNCATED 1
int hash_program_epilog(void *arg)
{
	struct hash_context *context = (struct hash_context *)arg;
	struct ccc_channel *channel = &context->channel;
	struct hash_data *data = ccc_get_channel_data(channel);
	struct ccc_dispatcher *dispatcher = context->dispatcher;
	struct operation op;

	/* If requested, T bit should be inserted here. */

	op = hash_get_opcode(channel->index, END, 2,
			     context->alg,
			     is_digest_truncation_supported(data) ?
			     FULL : T_RESET);
	ccc_program(dispatcher, op.code, op.wn, context->digest);

	return 0;
}

#define FROM_ALG_BITS(a, v) ((a) | ((v) << HASH_VERSION_SHIFT))
/* Return digest size in number of 32bits words. */
static inline unsigned int get_digest_size(struct hash_context *context)
{
	struct hash_data *data = ccc_get_channel_data(&context->channel);
	unsigned int size = 0;

	switch (FROM_ALG_BITS(context->alg, data->version)) {
	case HASH_MD5_ALG:
		size = 16 / 4;
		break;
	case HASH_SHA_1_ALG:
		size = 20 / 4;
		break;
	case HASH_SHA_224_ALG:
		size = (224 / 8) / 4;
		break;
	case HASH_SHA_256_ALG:
		size = (256 / 8) / 4;
		break;
	case HASH_SHA_384_ALG:
		size = (384 / 8) / 4;
		break;
	case HASH_SHA_512_ALG:
		size = (512 / 8) / 4;
		break;
	default:
		ASSERT(0);
		break;
	}

	return size;
}

void hash_post_processing(void *arg)
{
	struct hash_context *context = (struct hash_context *)arg;

	swap_bytes(context->digest, get_digest_size(context));
}

#define UHH_IR 0x1fc
static inline unsigned int read_uhh_ir(struct ccc_channel *c)
{
	return read_reg(c->base + UHH_IR);
}

static inline struct hash_context *get_context(void)
{
	struct hash_context *context = NULL;
	unsigned int i = ARRAY_SIZE(ctx) - 1;

	do {
		if (!ctx[i].inited) {
			context = &ctx[i];
			context->inited = true;
		}
	} while (i-- && !context);
	return context;
}

static inline struct hash_data *get_engine_data(int id)
{
	int i;

	for (i = uh_data.nr_id; i--;) {
		if (id == uh_data.ids[i])
			return &uh_data;
	}
	for (i = uh2_data.nr_id; i--;) {
		if (id == uh2_data.ids[i])
			return &uh2_data;
	}
	return NULL;
}

int hash_init(struct ccc_controller *c3, int index)
{
	struct hash_context *hash_context = get_context();
	struct ccc_channel *channel;
#ifdef DEBUG
	unsigned int scr;
#endif

	if (!hash_context)
		return -EBUSY;
	channel = &hash_context->channel;
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
	 * As channel capabilities regarding supported algorithms are determined
	 * by the channel ID, an unlisted ID will lead to reject some requested
	 * algorithms meant to be supported.
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
	TRACE_INFO(PREFIX "Cryptoblock Identification: %08x\n",
		   read_uhh_ir(channel));
#endif

	return 0;
}
