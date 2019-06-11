/**
 * @file sta_ccc.c
 * @brief CCC driver core.
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

#define DEV_NAME "ccc"
#define PREFIX DEV_NAME ": "

#define PROGRAMS_SIZE_IN_WORDS ((PROGRAM_SIZE_IN_BYTES / sizeof(unsigned int)) \
				* NR_DISPATCHERS)
unsigned int const _c3_programs[PROGRAMS_SIZE_IN_WORDS]
__attribute__((section(".c3_programs")));
#define PROGRAMS _c3_programs

struct crypto_context {
	struct ccc_dispatcher *dispatcher;
	bool randomize, cipher, cipher_sym, cipher_asym, move, hash;
	void *trng_context, *mpaes_context, *pka_context, *move_context,
		*hash_context;
};

struct ccc_context {
	struct ccc_controller controller;
	const unsigned int *programs;
	semaphore_t semaphore;
	struct crypto_context crypto_contexts[NR_DISPATCHERS];
};

static struct ccc_context ctx = {{0},};

struct walk {
	void *src;
	void *dst;
	unsigned int nr_bytes;
	struct ccc_scatter *scatter;
	unsigned int scatter_index;
};

bool is_in_place(struct ccc_scatter *scatter)
{
	unsigned int i;

	for (i = scatter->nr_entries; i--;) {
		struct entry *entry = &scatter->entries[i];

		if (entry->src != entry->dst)
			return false;
	}
	return true;
}

bool is_src_32bits_aligned(struct ccc_scatter *scatter)
{
	unsigned int i;

	for (i = scatter->nr_entries; i--;) {
		struct entry *entry = &scatter->entries[i];

		if (!THIRTY_TWO_BITS_ALIGNED((unsigned int)entry->src))
			return false;
	}
	return true;
}

bool is_dst_32bits_aligned(struct ccc_scatter *scatter)
{
	unsigned int i;

	for (i = scatter->nr_entries; i--;) {
		struct entry *entry = &scatter->entries[i];

		if (!THIRTY_TWO_BITS_ALIGNED((unsigned int)entry->dst))
			return false;
	}
	return true;
}

bool is_size_32bits_aligned(struct ccc_scatter *scatter)
{
	unsigned int i;

	for (i = scatter->nr_entries; i--;) {
		struct entry *entry = &scatter->entries[i];

		if (!THIRTY_TWO_BITS_ALIGNED(entry->size))
			return false;
	}
	return true;
}

bool is_size_null(struct ccc_scatter *scatter)
{
	unsigned int i;

	for (i = scatter->nr_entries; i--;) {
		struct entry *entry = &scatter->entries[i];

		if (!entry->size)
			return false;
	}
	return true;
}

bool is_size_multiple_of(struct ccc_scatter *scatter, unsigned int modulus)
{
	unsigned int i;

	for (i = scatter->nr_entries; i--;) {
		struct entry *entry = &scatter->entries[i];

		if (entry->size % modulus)
			return false;
	}
	return true;
}

bool is_src_dst_overlap(struct ccc_scatter *scatter)
{
	unsigned int i;

	for (i = scatter->nr_entries; i--;) {
		struct entry *entry = &scatter->entries[i];

		if ((((unsigned int)entry->dst > (unsigned int)entry->src)) &&
		    ((unsigned int)entry->dst <
		     ((unsigned int)entry->src + entry->size)))
			return false;
	}
	return true;
}

bool is_src_null(struct ccc_scatter *scatter)
{
	unsigned int i;

	for (i = scatter->nr_entries; i--;) {
		struct entry *entry = &scatter->entries[i];

		if (entry->src)
			return true;
	}
	return false;
}

static int walk_init(struct walk *walk, struct ccc_scatter *scatter)
{
	struct entry *entry;

	if (!walk || !scatter)
		return -EINVAL;
	if (scatter->control != SCATTER_CONTROL_WORD) {
		TRACE_INFO(PREFIX "Junk data\n");
		return -EINVAL;
	}
	walk->scatter = scatter;
	walk->scatter_index = 0;
	entry = &scatter->entries[walk->scatter_index];
	walk->src = entry->src;
	walk->dst = entry->dst;
	walk->nr_bytes = entry->size;
	return 0;
}

static int walk_done(struct walk *walk, unsigned int nr_bytes)
{
	struct ccc_scatter *scatter;
	struct entry *entry;
	unsigned int remaining;

	if (!walk)
		return -EINVAL;
	if (nr_bytes > walk->nr_bytes)
		return -EINVAL;
	scatter = walk->scatter;
	entry = &scatter->entries[walk->scatter_index];
	remaining = walk->nr_bytes - nr_bytes;
	walk->nr_bytes = nr_bytes;
	if (walk->nr_bytes == 0) {
		if (++walk->scatter_index >= scatter->nr_entries)
			return 0;
		entry++;
		walk->src = entry->src;
		walk->dst = entry->dst;
		walk->nr_bytes = entry->size;
	} else {
		walk->src += remaining;
		walk->dst += remaining;
	}
	return 0;
}

/*
 * chunk input points to chunks to program.
 * arg is not used.
 * req input handles the scatter buffers.
 * nr_chunks handles at input the number of chunks to program.
 * nr_chunks outputs the number of chunks actually programmed.
 */
bool ccc_prepare_chunks(struct ccc_chunk *chunk,
			__maybe_unused void *arg,
			struct ccc_crypto_req *req,
			unsigned int *nr_chunks)
{
	struct walk walk;
	unsigned int max_nr_chunks = *nr_chunks;
	unsigned int nr_bytes;

	if (walk_init(&walk, &req->scatter))
		return false;

	*nr_chunks = 0;
	while ((nr_bytes = walk.nr_bytes) > 0) {
		if (*nr_chunks >= max_nr_chunks) {
			TRACE_INFO(PREFIX "Data too big\n");
			return false;
		}
		chunk->in.size = MIN(nr_bytes, req->scatter.max_chunk_size);
		chunk->out.size = chunk->in.size;

		chunk->in.addr = walk.src;
		chunk->out.addr = walk.dst;
		nr_bytes -= chunk->in.size;

		walk_done(&walk, nr_bytes);
		chunk++;
		(*nr_chunks)++;
	}
	return true;
}

void ccc_set_channel_name(struct ccc_channel *channel, const char *name)
{
	ASSERT(channel);
	ASSERT(name);

	memset(channel->name, '\0', CCC_NAME_SIZE);
	strncpy(channel->name, name, CCC_NAME_SIZE - sizeof('\0'));
}

bool ccc_is_channel_supported(int id, const int *ids, unsigned int nr_id)
{
	if (!ids || !nr_id)
		return false;
	do {
		if (*ids == id)
			return true;
		ids++;
	} while (--nr_id);
	return false;
}

#define ARST (1 << 16)
static inline void ccc_reset(struct ccc_controller *c3)
{
	write_reg(ARST, c3->base + C3_SYS + SYS_SCR);
	udelay(1);
}

#define OP_ID_SHIFT 23
#define STOP 0
#define WAIT 1
#define CLOCK_CYCLES_SHIFT 0
#define NOP 3
#define COUPLE 6
#define MASTER_SHIFT 19
#define PORT_SHIFT 18
#define SLAVE_SHIFT 14
#define PATH_SHIFT 11
#define UNCOUPLE 7
struct operation ccc_get_opcode(unsigned char code, unsigned int nr_param, ...)
{
	struct operation op;
	va_list params;

	/* Flow type instructions make use of channel index 0. */
	switch (code) {
	case COUPLE:
		ASSERT(nr_param == 4);
		op.code = code << OP_ID_SHIFT;
		op.wn = 0;
		va_start(params, nr_param);
		op.code |= va_arg(params, unsigned int) << MASTER_SHIFT;
		op.code |= va_arg(params, unsigned int) << PORT_SHIFT;
		op.code |= va_arg(params, unsigned int) << SLAVE_SHIFT;
		op.code |= va_arg(params, unsigned int) << PATH_SHIFT;
		va_end(params);
		break;
	case UNCOUPLE:
		ASSERT(nr_param == 1);
		op.code = code << OP_ID_SHIFT;
		op.wn = 0;
		va_start(params, nr_param);
		op.code |= va_arg(params, unsigned int) << PATH_SHIFT;
		va_end(params);
		break;
	case STOP:
		ASSERT((nr_param == 1) || (nr_param == 0));
		op.code = code << OP_ID_SHIFT;
		/* Caller must take care of word0 if status is requested. */
		op.wn = nr_param ? 1 : 0;
		op.code |= op.wn << WN_SHIFT;
		break;
	case WAIT:
		ASSERT(nr_param == 1);
		op.code = code << OP_ID_SHIFT;
		op.wn = 0;
		va_start(params, nr_param);
		op.code |= va_arg(params, unsigned int) << CLOCK_CYCLES_SHIFT;
		va_end(params);
		break;
	case NOP:
		/* Fall through. */
	default:
		/* Can't fail. */
		op.code = NOP << OP_ID_SHIFT;
		op.wn = 0;
		break;
	}

	return op;
}

struct operation ccc_get_wait_opcode(unsigned short nr_cycles)
{
	return ccc_get_opcode(WAIT, 1, nr_cycles);
}

static inline bool is_dispatcher_busy(struct ccc_dispatcher *disp)
{
	unsigned int scr = ccc_read_id_scr(disp);
	unsigned int ids = ccc_get_dispatcher_status(scr);

	return (ids == S_BUSY);
}

#ifndef HAVE_INTERRUPT
static inline void init_completion(completion_t *completion,
				   struct ccc_dispatcher *disp)
{
	ASSERT(completion);
	ASSERT(disp);
	*completion = disp;
}

static inline void reinit_completion(__maybe_unused completion_t *completion)
{
}

static void wait_for_completion(completion_t *completion)
{
	struct ccc_dispatcher *disp = *completion;

	ASSERT(completion);
	ASSERT(disp);
	while (is_dispatcher_busy(disp))
		;
}

static inline void complete(__maybe_unused completion_t *completion)
{
}
#endif /* !HAVE_INTERRUPT */

static inline struct ccc_dispatcher *get_dispatcher(struct ccc_controller *c3,
						    unsigned int index)
{
	struct ccc_dispatcher *disp = &(c3->dispatchers[index]);

	disp->pc = disp->program.addr;
	reinit_completion(&disp->execution);

	return disp;
}

void ccc_program(struct ccc_dispatcher *d, unsigned int opcode,
		 unsigned char nr_param, ...)
{
	va_list params;

	ASSERT(d);

	/* Increase MAX_NR_INSTRUCTIONS if this assertion fails. */
	ASSERT(ccc_get_program_free_len(d) >=
	       (nr_param + 1) * sizeof(unsigned int));

	*d->pc++ = opcode;
	va_start(params, nr_param);
	while (nr_param) {
		unsigned int param = va_arg(params, unsigned int);

		*d->pc++ = param;
		nr_param--;
	}
	va_end(params);
}

#define BERR (1 << 29)
#define CERR (1 << 26)
#define CBSY (1 << 25)
#define CDNX (1 << 24)
static int report_dispatcher_error(struct ccc_dispatcher *disp)
{
	unsigned int scr = ccc_read_id_scr(disp);
	int ret = 0;

	if (scr & BERR) {
		ret = -EFAULT;
		TRACE_INFO(PREFIX "BERR\n");
	}
	if (scr & CERR) {
		ret = -ENOEXEC;
		TRACE_INFO(PREFIX "CERR\n");
	}
	if (scr & CBSY) {
		ret = -EBUSY;
		TRACE_INFO(PREFIX "CBSY\n");
	}
	if (scr & CDNX) {
		ret = -ENODEV;
		TRACE_INFO(PREFIX "CDNX\n");
	}

	if (!ret) {
		ret = -EIO;
		TRACE_INFO(PREFIX "Error handling error ");
	}

	return ret;
}

static int check_dispatcher_state(struct ccc_dispatcher *disp)
{
	unsigned int scr = ccc_read_id_scr(disp);
	unsigned int ids = ccc_get_dispatcher_status(scr);
	int ret = 0;

	switch (ids) {
	case S_ERROR:
		TRACE_INFO(PREFIX "Dispatcher in error state\n");
		/*
		 * Caller does not need to reset dispatcher as Error state
		 * will be exited at next program execution.
		 */
		ret = report_dispatcher_error(disp);
		break;
	case S_NOT_PRESENT:
		TRACE_INFO(PREFIX "Dispatcher not present\n");
		ret = -ENODEV;
		break;
	case S_BUSY:
		TRACE_INFO(PREFIX "Dispatcher busy\n");
		ret = -EBUSY;
		break;
	case S_IDLE:
		break;
	default:
		ret = -EFAULT;
		TRACE_INFO(PREFIX "Error handling error\n");
		break;
	}

	return ret;
}

#define INPUT_PORT 0
#define OUTPUT_PORT 1
static inline void program_prolog(struct crypto_context *context)
{
	int index;
	struct operation op;

	/*
	 * Coupling or chaining is requested only when hash is requested as
	 * well.
	 * Chaining HASH and PKA is not supported.
	 */
	if (context->hash) {
		index = hash_get_channel(context->hash_context)->index;
		if (context->cipher_sym) {
			/* Chain MPAES output to HASH input. */
			op = ccc_get_opcode(COUPLE, 4, MPAES_INDEX, OUTPUT_PORT,
					    index, MPAES_TO_HASH_PATH);
			ccc_program(context->dispatcher, op.code, op.wn);
		} else if (context->move) {
			/* Couple MOVE input to HASH input. */
			op = ccc_get_opcode(COUPLE, 4, MOVE_INDEX, INPUT_PORT,
					    index, MOVE_TO_HASH_PATH);
			ccc_program(context->dispatcher, op.code, op.wn);
		}
	}
}

static inline void program_epilog(struct crypto_context *context)
{
	struct operation op;

	if (context->hash) {
		if (context->cipher_sym) {
			/* Unchain MPAES and HASH. */
			op = ccc_get_opcode(UNCOUPLE, 1, MPAES_TO_HASH_PATH);
			ccc_program(context->dispatcher, op.code, op.wn);
		} else if (context->move) {
			/* Uncouple MOVE and HASH. */
			op = ccc_get_opcode(UNCOUPLE, 1, MOVE_TO_HASH_PATH);
			ccc_program(context->dispatcher, op.code, op.wn);
		}
	}

	op = ccc_get_opcode(STOP, 0);
	ccc_program(context->dispatcher, op.code, op.wn);
}

static int run_program(struct ccc_dispatcher *disp)
{
	ccc_dma_sync_for_device();
#ifdef HAVE_INTERRUPT
	ccc_enable_interrupts(disp);
#endif
	start_counter();
	ccc_set_instruction_pointer(disp);
	wait_for_completion(&disp->execution);

	return check_dispatcher_state(disp);
}

static void put_crypto_context(struct crypto_context *context)
{
	ASSERT(take_sem(ctx.semaphore));
	context->dispatcher = NULL;
	ASSERT(give_sem(ctx.semaphore));
}

static void close_program(struct crypto_context *context)
{
#if defined(LITTLE_ENDIAN) && defined(DISABLE_HIF_IF_CH_EN_SWAP)
	struct ccc_controller *c3 = context->dispatcher->controller;

	/* Set back HIF_IFCR.CH_END to normal value.*/
	if (context->move && context->hash) {
		ccc_set_hif_ifcr_ch_end(c3, true);
		TRACE_INFO(PREFIX "HIF_IFCR.CH_END is set.\n");
	}
#endif
	put_crypto_context(context);
}

void ccc_isr(void)
{
	struct ccc_controller *c3 = &(ctx.controller);
	struct ccc_dispatcher *disp = c3->dispatchers;
	unsigned char i;
	unsigned int scr, isdn;

	scr = ccc_read_sys_scr(c3);
	isdn = ccc_get_sys_scr_isdn(scr) & c3->en_dispatchers;
	for (i = c3->nr_dispatchers; i--;) {
		if (isdn & (1 << i)) {
			ccc_disable_interrupts(disp);
			ccc_clear_interrupt(disp);
			complete(&disp->execution);
		}
		disp++;
	}
}

static struct crypto_context *get_crypto_context(struct ccc_controller *c3)
{
	struct crypto_context *context = &(ctx.crypto_contexts[0]);
	struct crypto_context *found = NULL;
	unsigned int i = c3->nr_dispatchers;

	ASSERT(take_sem(ctx.semaphore));

	do {
		if (!context->dispatcher)
			found = context;
		context++;
	} while (--i && !found);

	if (found) {
		memset(found, 0, sizeof(*found));
		found->dispatcher = get_dispatcher(c3, i);
	}

	ASSERT(give_sem(ctx.semaphore));

	return found;
}

void *ccc_crypto_init(struct ccc_crypto_req *req)
{
	struct ccc_controller *c3 = &(ctx.controller);
	struct crypto_context *context;

	if (!req)
		return NULL;

	if (req->control != CRYPTO_REQ_CONTROL_WORD)
		return NULL;

	context = get_crypto_context(c3);
	if (!context)
		return NULL;

	/*
	 * Random number generation excludes all other operations.
	 */
	context->randomize = (req->randomize.alg != RNG_NONE_ALG);
	if (context->randomize) {
		context->trng_context = trng_crypto_init(req,
							 context->dispatcher);
		if (!context->trng_context)
			goto error;
		else
			return context;
	}

	/*
	 * Don't care of requested channels availability. Therefore if more than
	 * one context need it then its busy state will be reported.
	 */
	context->cipher_sym = (req->sym.alg != AES_NONE_ALG);
	context->cipher_asym = (req->asym.alg != PK_NONE_ALG);
	/*
	 * Support exclusively symmetric or asymmetric ciphering for the time
	 * being and until a new use-case requesting both is identified.
	 */
	if (context->cipher_sym && context->cipher_asym)
		goto error;
	context->cipher = context->cipher_sym || context->cipher_asym;
	if (context->cipher_sym) {
		context->mpaes_context = mpaes_crypto_init(req,
							   context->dispatcher);
		if (!context->mpaes_context)
			goto error;
	}
	if (context->cipher_asym) {
		context->pka_context = pka_crypto_init(req,
						       context->dispatcher);
		if (!context->pka_context)
			goto error;
	}

	/*
	 * Rely on PKA or MPAES to perform the move operation if ciphering is
	 * involved. Else let MOVE do the copy.
	 */
	context->move = !context->cipher && !is_in_place(&req->scatter);
	if (context->move) {
		context->move_context = move_crypto_init(req,
							 context->dispatcher);
		if (!context->move_context)
			goto error;
	}

	context->hash = (req->hash.alg != HASH_NONE_ALG);
	if (context->hash) {
		context->hash_context = hash_crypto_init(req,
							 context->dispatcher);
		if (!context->hash_context)
			goto error;

#if defined(LITTLE_ENDIAN) && defined(DISABLE_HIF_IF_CH_EN_SWAP)
		/*
		 * When coupling MOVE and HASH channel, input data are not
		 * swapped by HIF interface as expected and therefore HASH
		 * output is wrong.
		 * Consequently, in this use-case, HIF_IFCR.CH_END must be reset
		 * so that the 32-bit word input is swapped by HIF. Output word
		 * swapping must be done by software.
		 *
		 * As HIF_IFCR.CH_END scope is the whole C3, other channels will
		 * misbehave.
		 */
		if (context->move) {
			ccc_set_hif_ifcr_ch_end(c3, false);
			TRACE_INFO(PREFIX "HIF_IFCR.CH_END is reset.\n");
		}
#endif
	}

	if (!(context->cipher || context->move || context->hash)) {
		TRACE_INFO(PREFIX "Told to do nothing\n");
		goto error;
	}

	 /*
	  * Chaining HASH and PKA is not supported.
	  * This could be useful in order to sign some data.
	  */
	if (context->hash && context->cipher_asym) {
		TRACE_INFO(PREFIX "Chaining HASH and PKA is not supported\n");
		goto error;
	}

	return context;
error:
	put_crypto_context(context);
	return NULL;
}

static int report_channel_error(struct ccc_channel *channel)
{
	unsigned int scr = ccc_read_channel_scr(channel);
	int ret = 0;

	if (scr & BERR & channel->error_mask) {
		ret = -EFAULT;
		TRACE_INFO(PREFIX "%s: BERR\n", channel->name);
	}
	if (scr & DERR & channel->error_mask) {
		ret = -ENOEXEC;
		TRACE_INFO(PREFIX "%s: DERR\n", channel->name);
	}
	if (scr & PERR & channel->error_mask) {
		ret = -EBUSY;
		TRACE_INFO(PREFIX "%s: PERR\n", channel->name);
	}
	if (scr & IERR & channel->error_mask) {
		ret = -ENODEV;
		TRACE_INFO(PREFIX "%s: IERR\n", channel->name);
	}
	if (scr & AERR & channel->error_mask) {
		ret = -ENODEV;
		TRACE_INFO(PREFIX "%s: AERR\n", channel->name);
	}
	if (scr & OERR & channel->error_mask) {
		ret = -ENODEV;
		TRACE_INFO(PREFIX "%s: OERR\n", channel->name);
	}

	if (!ret) {
		ret = -EIO;
		TRACE_INFO(PREFIX "%s: Error handling error\n",
			   channel->name);
		ASSERT(0);
	}

	return ret;
}

static int check_channel_state(struct ccc_channel *channel)
{
	unsigned int scr = ccc_read_channel_scr(channel);
	unsigned int cs = ccc_get_channel_status(scr);
	int ret = 0;

	switch (cs) {
	case S_ERROR:
		TRACE_INFO(PREFIX "Channel in error state\n");
		/*
		 * Caller does not need to reset channel as Error state will be
		 * exited at next program execution.
		 */
		ret = report_channel_error(channel);
		break;
	case S_NOT_PRESENT:
		TRACE_INFO(PREFIX "%s: Channel not present\n", channel->name);
		ret = -ENODEV;
		break;
	case S_BUSY:
		TRACE_INFO(PREFIX "%s: Channel busy\n", channel->name);
		ret = -EBUSY;
		break;
	case S_IDLE:
		break;
	default:
		ret = -EFAULT;
		TRACE_INFO(PREFIX "%s: Error handling error\n", channel->name);
		ASSERT(0);
		break;
	}

	return ret;
}

int ccc_crypto_run(void *arg)
{
	struct crypto_context *context = (struct crypto_context *)arg;
	struct ccc_channel *channel;
	int ret;

	program_prolog(context);

	if (context->randomize) {
		ret = trng_program_prolog(context->trng_context);
		if (ret)
			goto exit;
	} else {
		if (context->hash) {
			ret = hash_program_prolog(context->hash_context);
			if (ret)
				goto exit;
		}

		/* MPAES and PKA usage is exclusive. */
		if (context->cipher_sym) {
			ret = mpaes_program_prolog(context->mpaes_context);
			if (ret)
				goto exit;
		} else if (context->cipher_asym) {
			ret = pka_program_prolog(context->pka_context);
			if (ret)
				goto exit;
		}
	}

	if (context->randomize) {
		ret = trng_program(context->trng_context);
		if (ret)
			goto exit;
	} else {
		if (context->move) {
			ret = move_program(context->move_context);
			if (ret)
				goto exit;
		}

		if (context->hash) {
			ret = hash_program(context->hash_context);
			if (ret)
				goto exit;
		}

		/*
		 * MPAES precedes HASH because integrity must be checked after
		 * decryption.
		 */
		if (context->cipher_sym) {
			ret = mpaes_program(context->mpaes_context);
			if (ret)
				goto exit;

			ret = mpaes_program_epilog(context->mpaes_context);
			if (ret)
				goto exit;
		}

		if (context->hash) {
			ret = hash_program_epilog(context->hash_context);
			if (ret)
				goto exit;
		}

		/* PKA should follow HASH in a signing perspective. */
		if (context->cipher_asym) {
			ret = pka_program(context->pka_context);
			if (ret)
				goto exit;

			ret = pka_program_epilog(context->pka_context);
			if (ret)
				goto exit;
		}
	}

	program_epilog(context);
	ret = run_program(context->dispatcher);

	if (context->randomize) {
		channel = trng_get_channel(context->trng_context);
		ASSERT(channel);
		ret |= check_channel_state(channel);
	}

	/* MPAES and PKA usage is exclusive. */
	if (context->cipher_sym) {
		channel = mpaes_get_channel(context->mpaes_context);
		ASSERT(channel);
		ret |= check_channel_state(channel);
		if (!ret)
			mpaes_post_processing(context->mpaes_context);
	} else if (context->cipher_asym) {
		channel = pka_get_channel(context->pka_context);
		ASSERT(channel);
		ret |= check_channel_state(channel);
		if (!ret)
			ret = pka_post_processing(context->pka_context);
	}

	if (context->move) {
		channel = move_get_channel(context->move_context);
		ASSERT(channel);
		ret |= check_channel_state(channel);
	}

	if (context->hash) {
		channel = hash_get_channel(context->hash_context);
		ret |= check_channel_state(channel);
#if defined(LITTLE_ENDIAN) && defined(DISABLE_HIF_IF_CH_EN_SWAP)
		/* Process output data by CPU. */
		if (!ret && context->move)
			hash_post_processing(context->hash_context);
#endif
	}

exit:
	close_program(context);
	return ret;
}

int dispatchers_init(struct ccc_controller *c3)
{
	int i;
	struct ccc_dispatcher *disp;
	unsigned int scr;

	c3->nr_dispatchers = NR_DISPATCHERS;
	c3->en_dispatchers = EN_DISPATCHERS;
	ctx.programs = PROGRAMS;

	scr = ccc_read_sys_scr(c3);
	disp = &(c3->dispatchers[0]);
	for (i = c3->nr_dispatchers; i--; ) {
		if (!ccc_is_indexed_dispatcher_present(scr, i))
			return -EINVAL;

		disp->base = c3->base + C3_ID(i);
		disp->program.addr = (unsigned int *)ctx.programs;
		disp->program.addr += i * PROGRAM_SIZE_IN_BYTES;
		disp->program.size = PROGRAM_SIZE_IN_BYTES;
		disp->index = i;
		disp->pc = 0;
		init_completion(&disp->execution, disp);
		disp->controller = c3;
		disp++;
	}

	return 0;
}

#ifdef HAVE_INTERRUPT
static inline int irq_init(struct ccc_controller *c3)
{
	struct nvic_chnl *irq_chnl = &c3->irq_chnl;

	irq_chnl->id = C3_IRQ_ID;
	irq_chnl->preempt_prio = IRQ_LOW_PRIO;
	irq_chnl->enabled = true;

	return nvic_chnl_init(irq_chnl);
}

static inline void irq_deinit(struct ccc_controller *c3)
{
	nvic_chnl_disable(&c3->irq_chnl);
}
#endif

/*
 * Platform definitions might have been passed here instead of including
 * "sta_ccc_plat.h".
 */
int ccc_init(void)
{
	struct ccc_controller *c3 = &(ctx.controller);
#ifdef DEBUG
	unsigned int scr, ver, ifcr;
#endif
	int err;

	/*
	 * This init function should be only once by the hardware setup.
	 * Nevertheless there is no need to use a semaphore because there is no
	 * concurrent access during init.
	 */
	if (c3->base == C3_BASE) {
		TRACE_ERR(PREFIX "Already inited\n");
		return -EEXIST;
	}
	c3->base = C3_BASE;

#ifdef HAVE_INTERRUPT
	err = irq_init(c3);
	if (err)
		return err;
#endif

	/* Requested c3_clk clock is enabled. */

	ctx.semaphore = create_sem();
	ASSERT(ctx.semaphore);
	ASSERT(give_sem(ctx.semaphore));

	err = dispatchers_init(c3);
	if (err)
		return err;

#ifdef DEBUG
	/*
	 * Endianness control bits meaning interpretation dumped below is
	 * subject to caution.
	 * Most C3 channels are natively big-endian. Therefore on little-endian
	 * platforms, channel io must be swapped by HIF interface.
	 */
	ver = ccc_read_sys_ver(c3);
	TRACE_INFO(PREFIX "Hardware Version: %d.%d.%d\n",
		   ccc_get_sys_ver_v(ver),
		   ccc_get_sys_ver_r(ver),
		   ccc_get_sys_ver_s(ver));
	scr = ccc_read_sys_scr(c3);
	TRACE_INFO(PREFIX "Clear Interrupts on SYS_SCR Read: %s\n",
		   ccc_get_sys_scr_cisr(scr) ? "yes" : "no");
	TRACE_INFO(PREFIX "SIF Endianness: %s\n",
		   ccc_get_sys_scr_endian(scr) ? "little" : "big");
	TRACE_INFO(PREFIX "%d Instruction Dispatcher%s enabled\n",
		   c3->nr_dispatchers, c3->nr_dispatchers > 1 ? "s" : "");
	TRACE_INFO(PREFIX "HIF memory size: %dB\n",
		   ccc_read_hif_memory_size(c3));
	ifcr = ccc_read_hif_ifcr(c3);
	TRACE_INFO(PREFIX "HIF Instructions Dispatchers Endianness: %s\n",
		   ccc_get_hif_ifcr_id_end(ifcr) ? "little" : "big");
	TRACE_INFO(PREFIX "HIF Channels Endianness: %s\n",
		   ccc_get_hif_ifcr_ch_end(ifcr) ? "little" : "big");
#endif

	/* Initializations of implemented channels. */
#ifdef TRNG_INDEX
	trng_init(c3, TRNG_INDEX);
#endif
#ifdef MPAES_INDEX
	mpaes_init(c3, MPAES_INDEX, SP_KEY_SLOTS, GP_KEY_SLOTS);
#endif
#ifdef PKA_INDEX
	pka_init(c3, PKA_INDEX);
#endif
#ifdef MOVE_INDEX
	move_init(c3, MOVE_INDEX);
#endif
#ifdef UH_INDEX
	hash_init(c3, UH_INDEX);
#endif
#ifdef UH2_INDEX
	hash_init(c3, UH2_INDEX);
#endif
	return 0;
}

void ccc_deinit(void)
{
	struct ccc_controller *c3 = &(ctx.controller);

#ifdef HAVE_INTERRUPT
	irq_deinit(c3);
#endif
	ccc_reset(c3);
}
