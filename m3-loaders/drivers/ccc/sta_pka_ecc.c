/**
 * @file sta_pka_ecc.c
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

#define PREFIX DEV_NAME ": ecc: "

#define MONTY_PAR_IN_SIZE(d) (sizeof((d)->monty_par_in.op_len) +	\
			      (d)->op_len_in_bytes)

#define ECC_MONTY_MUL_SIZE(d) (sizeof((d)->op_len_in_bytes) +	\
			       (d)->op_len_in_bytes +		\
			       sizeof(unsigned int) +		\
			       (d)->op_len_in_bytes +		\
			       2 * (d)->op_len_in_bytes +	\
			       sizeof((d)->k_len_in_bytes) +	\
			       (d)->k_len_in_bytes)

#define ECC_MUL_SIZE(d) (ECC_MONTY_MUL_SIZE(d) + \
			 (d)->op_len_in_bytes +	\
			 (ODD((d)->op_len_in_bytes / sizeof(unsigned int)) ? \
			  sizeof(unsigned int) : 0))

#define ECC_SIZE_IN_WORDS SIZE_IN_WORDS(MAX_ECC_SIZE_IN_BITS)

struct montgomery_parameter_input {
	unsigned int op_len;
	unsigned int mod[ECC_SIZE_IN_WORDS];
};

struct montgomery_parameter {
	/*
	 * Reserve one more 32bits word for Montgomery parameter in case of an
	 * odd number of words of modulus.
	 */
	unsigned int square_r[ECC_SIZE_IN_WORDS + 1];
};

struct ecc_multiplication {
	unsigned int op_len;
	unsigned int mod[ECC_SIZE_IN_WORDS];
	unsigned int a_sign;
	unsigned int a[ECC_SIZE_IN_WORDS];
	unsigned int p[2 * ECC_SIZE_IN_WORDS];
	unsigned int k_len;
	unsigned int k[ECC_SIZE_IN_WORDS];
	/*
	 * Reserve one more 32bits word for Montgomery parameter in case of an
	 * odd number of words of modulus.
	 */
	unsigned int square_r[ECC_SIZE_IN_WORDS + 1];
};

struct ecc_montgomery_multiplication {
	unsigned int op_len;
	unsigned int mod[ECC_SIZE_IN_WORDS];
	unsigned int a_sign;
	unsigned int a[ECC_SIZE_IN_WORDS];
	unsigned int p[2 * ECC_SIZE_IN_WORDS];
	unsigned int k_len;
	unsigned int k[ECC_SIZE_IN_WORDS];
};

struct pka_shared_data {
	struct montgomery_parameter_input monty_par_in;
	struct montgomery_parameter *monty_par;
	struct ecc_montgomery_multiplication ecc_monty_mul;
	struct ecc_multiplication ecc_mul[ECC_NR_CHUNKS];
	/* Lengths copy to ease access. */
	unsigned int op_len_in_bytes, k_len_in_bytes;
};

/*
 * Cryptographic materials memory region shared with PKA channel.
 */
struct pka_shared_data _pka_ecc_shared_data
__aligned(4) __attribute__((section(".c3_programs")));

static void set_monty_par_in(struct pka_shared_data *data,
			     struct ccc_crypto_req *req)
{
	struct montgomery_parameter_input *monty_par_in = &data->monty_par_in;

	monty_par_in->op_len = get_dimension(req->asym.modulus,
					     req->asym.modulus_size);
	swap_bytes_if((unsigned char *)&monty_par_in->op_len,
		      sizeof(unsigned int));
	memcpy(monty_par_in->mod, req->asym.modulus, req->asym.modulus_size);
}

static void set_monty_par(struct pka_shared_data *data,
			  struct pka_context *context)
{
	/*
	 * Output Montgomery parameter calculation in scalar multiplication
	 * input.
	 */
	data->monty_par = (struct montgomery_parameter *)
		((unsigned char *)&data->ecc_mul +
		 context->nr_chunks * ECC_MONTY_MUL_SIZE(data));
}

/*
 * If 'req' is not null and index is zero then fill ECC_MUL input structure at
 * index 0 as a template for further calls and leave point P coordinates
 * untouched.
 * If 'req' is null and index is not zero then copy ECC_MUL input structure at
 * index 0 into ECC_MUL input structure indexed by 'index' and copy point P
 * coordinates.
 */
static int set_ecc_mul(struct pka_shared_data *data,
		       struct ccc_crypto_req *req,
		       unsigned int index,
		       unsigned char *point)
{
	int ret;
	unsigned char *p = (unsigned char *)&data->ecc_mul[index];
	unsigned int a_sign_size = sizeof(unsigned int);

	if (!index && !req)
		return -EINVAL;

	if (req) {
		struct curve *curve = &req->asym.curve;
		unsigned int a_size;

		/* Append modulus. */
		data->op_len_in_bytes = 0;
		ret = append_bignum(&p, req->asym.modulus,
				    req->asym.modulus_size,
				    &data->op_len_in_bytes);
		if (ret)
			return ret;

		/* Append 'a' parameter sign. */
		ret = append_bignum(&p, (unsigned char *)&curve->a_sign,
				    sizeof(curve->a_sign), &a_sign_size);
		if (ret)
			return ret;

		/* Append 'a' parameter. */
		a_size = req->asym.modulus_size;
		ret = append_bignum(&p, curve->a, a_size, &a_size);
		if (ret)
			return ret;

		/* Skip base point P. */
		p += 2 * ROUND_UP(req->asym.modulus_size, sizeof(unsigned int));

		/* Append scalar k. */
		data->k_len_in_bytes = 0;
		ret = append_bignum(&p, req->asym.k, req->asym.k_size,
				    &data->k_len_in_bytes);
		if (ret)
			return ret;

		/*
		 * Update modulus and scalar sizes to their actual value i.e
		 * rounded to the size of words needed to represent them.
		 */
		data->op_len_in_bytes = ROUND_UP(data->op_len_in_bytes,
						 sizeof(unsigned int));
		data->k_len_in_bytes = ROUND_UP(data->k_len_in_bytes,
						sizeof(unsigned int));
		ASSERT(p == (unsigned char *)&data->ecc_mul[index] +
		       ECC_MUL_SIZE(data));
	} else {
		struct ecc_multiplication *ecc_mul_template =
			&data->ecc_mul[0];

		/* Copy template. */
		memcpy(p, (unsigned char *)ecc_mul_template,
		       sizeof(*ecc_mul_template));

		/* Move to base point P location. */
		p += data->op_len_in_bytes + a_sign_size +
			data->op_len_in_bytes;

		/* Insert point P. */
		memcpy(p, point, data->op_len_in_bytes);
	}
	return 0;
}

static int set_ecc_monty_mul(struct pka_shared_data *data,
			     struct ccc_crypto_req *req,
			     unsigned char *point)
{
	int ret;
	unsigned char *p = (unsigned char *)&data->ecc_monty_mul;
	unsigned int a_sign_size = sizeof(unsigned int), p_size;
	struct curve *curve = &req->asym.curve;

	/* Append modulus. */
	data->op_len_in_bytes = 0;
	ret = append_bignum(&p, req->asym.modulus, req->asym.modulus_size,
			    &data->op_len_in_bytes);
	if (ret)
		return ret;

	/* Append 'a' parameter sign. */
	ret = append_bignum(&p, (unsigned char *)&curve->a_sign,
			    sizeof(curve->a_sign), &a_sign_size);
	if (ret)
		return ret;

	/*
	 * 'a' parameter, Px and Py big numbers are meant to be as big
	 * as modulus.
	 * Append 'a' parameter.
	 */
	ret = append_bignum(&p, curve->a, req->asym.modulus_size,
			    &data->op_len_in_bytes);
	if (ret)
		return ret;

	/* Append base point P. */
	p_size = 2 * ROUND_UP(req->asym.modulus_size, sizeof(unsigned int));
	ret = append_bignum(&p, point, p_size, &p_size);
	if (ret)
		return ret;

	/* Append scalar k. */
	data->k_len_in_bytes = 0;
	ret = append_bignum(&p, req->asym.k, req->asym.k_size,
			    &data->k_len_in_bytes);
	if (ret)
		return ret;

	/*
	 * Update modulus and scalar sizes to their actual value i.e
	 * rounded to the size of words needed to represent them.
	 */
	data->op_len_in_bytes = ROUND_UP(data->op_len_in_bytes,
					 sizeof(unsigned int));
	data->k_len_in_bytes = ROUND_UP(data->k_len_in_bytes,
					sizeof(unsigned int));
	ASSERT(p == (unsigned char *)&data->ecc_monty_mul +
	       ECC_MONTY_MUL_SIZE(data));

	return 0;
}

void *ecc_crypto_init(struct ccc_crypto_req *req,
		      struct pka_context *context)
{
	struct pka_shared_data *data;
	struct curve *curve = &req->asym.curve;

	if (!req->asym.modulus) {
		TRACE_INFO(PREFIX "Modulus null pointer\n");
		return NULL;
	}
	if (!ecc_check_modulus_size(req->asym.modulus_size)) {
		TRACE_INFO(PREFIX "Bad modulus size\n");
		return NULL;
	}
	if (!*(unsigned int *)&req->asym.modulus[0]) {
		TRACE_INFO(PREFIX "First 32bits word of ECC modulus is zero\n");
		return NULL;
	}
	if (!get_dimension(req->asym.modulus, req->asym.modulus_size)) {
		TRACE_INFO(PREFIX "Modulus is zero\n");
		return NULL;
	}
	if (!curve->a) {
		TRACE_INFO(PREFIX "'a' parameter null pointer\n");
		return NULL;
	}
	if (!req->asym.k) {
		TRACE_INFO(PREFIX "'k' parameter null pointer\n");
		return NULL;
	}
	if (!ecc_check_scalar_size(req->asym.k_size)) {
		TRACE_INFO(PREFIX "Bad 'k' len\n");
		return NULL;
	}

	/* PKA input is always in memory. */
	if (req->scatter.nr_bytes == 0) {
		TRACE_INFO(PREFIX "No data to compute\n");
		return NULL;
	}
	if (!is_size_multiple_of(&req->scatter,
				 2 * ROUND_UP(req->asym.modulus_size,
					      sizeof(unsigned int)))) {
		TRACE_INFO(PREFIX "Data size not multiple of modulus size\n");
		return NULL;
	}
	if (!is_src_32bits_aligned(&req->scatter) ||
	    !is_dst_32bits_aligned(&req->scatter)) {
		TRACE_INFO(PREFIX "Data not aligned on 32bits\n");
		return NULL;
	}

	/* Update max chunk size constraint. */
	req->scatter.max_chunk_size = 2 * ROUND_UP(req->asym.modulus_size,
						   sizeof(unsigned int));
	context->nr_chunks = ECC_NR_CHUNKS;
	if (!ccc_prepare_chunks(&context->chunks[0], NULL, req,
				&context->nr_chunks))
		return NULL;

	context->data = &_pka_ecc_shared_data;
	data = context->data;
	memset(data, '\0', sizeof(_pka_ecc_shared_data));

	if (context->nr_chunks > 1) {
		set_monty_par_in(data, req);
		/* Set ECC_MUL input data structure template. */
		if (set_ecc_mul(data, req, 0, NULL))
			return NULL;
		set_monty_par(data, context);
	} else {
		/* Set ECC_MONTY_MUL input data structure. */
		if (set_ecc_monty_mul(data, req, context->chunks[0].in.addr))
			return NULL;
	}

	return context;
}

#define ECC_MUL 0x16
#define ECC_MONTY_MUL 0x17
static struct operation ecc_get_opcode(int index, unsigned char code,
				       unsigned int nr_param, ...)
{
	struct operation op;
	va_list params;

	switch (code) {
	case ECC_MUL:
		ASSERT(nr_param == 2);
		op.code = code << OP_ID_SHIFT;
		op.wn = 2;
		va_start(params, nr_param);
		op.code |= va_arg(params, unsigned int) << COUNTERMEASURE_SHIFT;
		op.code |= va_arg(params, unsigned int) << LENGTH_SHIFT;
		va_end(params);
		break;
	case ECC_MONTY_MUL:
		ASSERT(nr_param == 2);
		op.code = code << OP_ID_SHIFT;
		op.wn = 2;
		va_start(params, nr_param);
		op.code |= va_arg(params, unsigned int) << COUNTERMEASURE_SHIFT;
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

void ecc_program_prolog(struct pka_context *context)
{
	if (context->nr_chunks > 1) {
		/*
		 * If there is more than one scalar multiplication to perform
		 * then compute Montgomery parameter once for all.
		 */
		struct ccc_channel *channel = &context->channel;
		struct ccc_dispatcher *dispatcher = context->dispatcher;
		struct operation op;
		struct pka_shared_data *data = context->data;

		op = get_opcode(channel->index, MONTY_PAR, 1,
				MONTY_PAR_IN_SIZE(data));
		ccc_program(dispatcher, op.code, op.wn,
			    &data->monty_par_in,
			    data->monty_par);
	}
}

void ecc_program(struct pka_context *context)
{
	struct ccc_channel *channel = &context->channel;
	struct ccc_dispatcher *dispatcher = context->dispatcher;
	struct operation op;
	struct pka_shared_data *data = context->data;
	struct ccc_chunk *chunk = &context->chunks[0];

	if (context->nr_chunks > 1) {
		unsigned int i;

		for (i = 0; i < context->nr_chunks; i++) {
			set_ecc_mul(data, NULL, i, chunk->in.addr);
			op = ecc_get_opcode(channel->index, ECC_MUL, 2,
					    PKA_POWER_ANALYSIS_COUNTERMEASURE,
					    ECC_MUL_SIZE(data));
			ccc_program(dispatcher, op.code, op.wn,
				    &data->ecc_mul,
				    chunk->out.addr);
			chunk++;
		}
	} else {
		op = ecc_get_opcode(channel->index, ECC_MONTY_MUL, 2,
				    PKA_POWER_ANALYSIS_COUNTERMEASURE,
				    ECC_MONTY_MUL_SIZE(data));
		ccc_program(dispatcher, op.code, op.wn,
			    &data->ecc_monty_mul,
			    chunk->out.addr);
	}
}

struct pka_alg pka_ecc_alg = {
	.crypto_init = ecc_crypto_init,
	.program_prolog = ecc_program_prolog,
	.program = ecc_program,
};
