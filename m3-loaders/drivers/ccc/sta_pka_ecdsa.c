/**
 * @file sta_pka_ecdsa.c
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

#define PREFIX DEV_NAME ": ecdsa: "

#define ECDSA_SIGN_SIZE(d) (sizeof((d)->op_len_in_bytes) +	\
			    (d)->op_len_in_bytes +		\
			    sizeof(unsigned int) +		\
			    (d)->op_len_in_bytes +		\
			    2 * (d)->op_len_in_bytes +		\
			    sizeof((d)->n_len_in_bytes) +	\
			    (d)->n_len_in_bytes +		\
			    (d)->n_len_in_bytes +		\
			    (d)->n_len_in_bytes +		\
			    (d)->n_len_in_bytes)

#define ECDSA_SIGNATURE_SIZE(d) ((d)->n_len_in_bytes +	\
				 (d)->n_len_in_bytes)

#define ECDSA_VERIFY_SIZE(d) (sizeof((d)->op_len_in_bytes) +	\
			      (d)->op_len_in_bytes +		\
			      sizeof(unsigned int) +		\
			      (d)->op_len_in_bytes +		\
			      2 * (d)->op_len_in_bytes +	\
			      2 * (d)->op_len_in_bytes +	\
			      sizeof((d)->n_len_in_bytes) +	\
			      (d)->n_len_in_bytes +		\
			      (d)->n_len_in_bytes +		\
			      (d)->n_len_in_bytes +		\
			      (d)->n_len_in_bytes)

#define ECC_SIZE_IN_WORDS SIZE_IN_WORDS(MAX_ECC_SIZE_IN_BITS)

struct ecdsa_sign {
	unsigned int op_len;
	unsigned int mod[ECC_SIZE_IN_WORDS];
	unsigned int a_sign;
	unsigned int a[ECC_SIZE_IN_WORDS];
	unsigned int p[2 * ECC_SIZE_IN_WORDS];
	unsigned int n_len;
	unsigned int n[ECC_SIZE_IN_WORDS];
	unsigned int d[ECC_SIZE_IN_WORDS];
	unsigned int k[ECC_SIZE_IN_WORDS];
	unsigned int e[ECC_SIZE_IN_WORDS];
};

struct ecdsa_signature {
	unsigned int fault;
	unsigned int r[ECC_SIZE_IN_WORDS];
	unsigned int s[ECC_SIZE_IN_WORDS];
};

struct ecdsa_verify {
	unsigned int op_len;
	unsigned int mod[ECC_SIZE_IN_WORDS];
	unsigned int a_sign;
	unsigned int a[ECC_SIZE_IN_WORDS];
	unsigned int p[2 * ECC_SIZE_IN_WORDS];
	unsigned int q[2 * ECC_SIZE_IN_WORDS];
	unsigned int n_len;
	unsigned int n[ECC_SIZE_IN_WORDS];
	unsigned int r[ECC_SIZE_IN_WORDS];
	unsigned int s[ECC_SIZE_IN_WORDS];
	unsigned int e[ECC_SIZE_IN_WORDS];
};

struct ecdsa_verification {
	unsigned int fault;
};

struct pka_shared_data {
	bool is_generation;
	struct ecdsa_sign ecdsa_sign;
	struct ecdsa_verify ecdsa_verify;
	unsigned int op_len_in_bytes, n_len_in_bytes;
	char output[MAX(sizeof(struct ecdsa_signature),
			sizeof(struct ecdsa_verification))];
};

/*
 * Cryptographic materials memory region shared with PKA channel.
 */
struct pka_shared_data _pka_ecdsa_shared_data
__aligned(4) __attribute__((section(".c3_programs")));

static int set_ecdsa_sign(struct pka_shared_data *data,
			  struct ccc_crypto_req *req,
			  unsigned char *point)
{
	int ret;
	unsigned char *p = (unsigned char *)&data->ecdsa_sign;
	unsigned int a_sign_size, a_size, p_size, d_size, k_size, e_size;

	if (!req)
		return -EINVAL;

	struct curve *curve = &req->asym.curve;

	/* Append modulus. */
	data->op_len_in_bytes = 0;
	ret = append_bignum(&p, req->asym.modulus,
			    req->asym.modulus_size,
			    &data->op_len_in_bytes);
	if (ret)
		return ret;

	/* Append 'a' parameter sign. */
	a_sign_size = sizeof(unsigned int);
	ret = append_bignum(&p, (unsigned char *)&curve->a_sign,
			    sizeof(curve->a_sign), &a_sign_size);
	if (ret)
		return ret;

	/* Append 'a' parameter. */
	a_size = req->asym.modulus_size;
	ret = append_bignum(&p, curve->a, a_size, &a_size);
	if (ret)
		return ret;

	/* Append point P. */
	p_size = 2 * ROUND_UP(req->asym.modulus_size, sizeof(unsigned int));
	ret = append_bignum(&p, point, p_size, &p_size);
	if (ret)
		return ret;

	/* Append order n. */
	data->n_len_in_bytes = 0;
	ret = append_bignum(&p, curve->n, curve->n_size,
			    &data->n_len_in_bytes);
	if (ret)
		return ret;

	/* Append secret key d. */
	d_size = data->n_len_in_bytes;
	ret = append_bignum(&p, curve->d, d_size, &d_size);
	if (ret)
		return ret;

	/* Append random k. */
	k_size = data->n_len_in_bytes;
	ret = append_bignum(&p, curve->k, k_size, &k_size);
	if (ret)
		return ret;

	/* Append hash e. */
	e_size = data->n_len_in_bytes;
	ret = append_bignum(&p, curve->e, e_size, &e_size);
	if (ret)
		return ret;

	/*
	 * Update modulus and order sizes to their actual value i.e rounded to
	 * the size of words needed to represent them.
	 */
	data->op_len_in_bytes = ROUND_UP(data->op_len_in_bytes,
					 sizeof(unsigned int));
	data->n_len_in_bytes = ROUND_UP(data->n_len_in_bytes,
					sizeof(unsigned int));
	ASSERT(p == (unsigned char *)&data->ecdsa_sign + ECDSA_SIGN_SIZE(data));

	return 0;
}

static int set_ecdsa_verify(struct pka_shared_data *data,
			    struct ccc_crypto_req *req,
			    unsigned char *point)
{
	int ret;
	unsigned char *p = (unsigned char *)&data->ecdsa_verify;
	unsigned int a_sign_size, a_size, p_size, q_size, r_size,
		s_size, e_size;

	if (!req)
		return -EINVAL;

	struct curve *curve = &req->asym.curve;

	/* Append modulus. */
	data->op_len_in_bytes = 0;
	ret = append_bignum(&p, req->asym.modulus,
			    req->asym.modulus_size,
			    &data->op_len_in_bytes);
	if (ret)
		return ret;

	/* Append 'a' parameter sign. */
	a_sign_size = sizeof(unsigned int);
	ret = append_bignum(&p, (unsigned char *)&curve->a_sign,
			    sizeof(curve->a_sign), &a_sign_size);
	if (ret)
		return ret;

	/* Append 'a' parameter. */
	a_size = req->asym.modulus_size;
	ret = append_bignum(&p, curve->a, a_size, &a_size);
	if (ret)
		return ret;

	/* Append base point P. */
	p_size = 2 * ROUND_UP(req->asym.modulus_size, sizeof(unsigned int));
	ret = append_bignum(&p, point, p_size, &p_size);
	if (ret)
		return ret;

	/* Append public key point Q. */
	q_size = 2 * ROUND_UP(req->asym.modulus_size, sizeof(unsigned int));
	ret = append_bignum(&p, curve->q, q_size, &q_size);
	if (ret)
		return ret;

	/* Append order n. */
	data->n_len_in_bytes = 0;
	ret = append_bignum(&p, curve->n, curve->n_size,
			    &data->n_len_in_bytes);
	if (ret)
		return ret;

	/* Append first part of the signature to be verified r. */
	r_size = data->n_len_in_bytes;
	ret = append_bignum(&p, curve->r, r_size, &r_size);
	if (ret)
		return ret;

	/* Append second part of the signature to be verified s. */
	s_size = data->n_len_in_bytes;
	ret = append_bignum(&p, curve->s, s_size, &s_size);
	if (ret)
		return ret;

	/* Append hash e. */
	e_size = data->n_len_in_bytes;
	ret = append_bignum(&p, curve->e, e_size, &e_size);
	if (ret)
		return ret;

	/*
	 * Update modulus and order sizes to their actual value i.e rounded to
	 * the size of words needed to represent them.
	 */
	data->op_len_in_bytes = ROUND_UP(data->op_len_in_bytes,
					 sizeof(unsigned int));
	data->n_len_in_bytes = ROUND_UP(data->n_len_in_bytes,
					sizeof(unsigned int));
	ASSERT(p ==
	       (unsigned char *)&data->ecdsa_verify + ECDSA_VERIFY_SIZE(data));

	return 0;
}

void *ecdsa_crypto_init(struct ccc_crypto_req *req,
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
	if (!curve->n) {
		TRACE_INFO(PREFIX "'n' parameter null pointer\n");
		return NULL;
	}
	if (!ecc_check_scalar_size(curve->n_size)) {
		TRACE_INFO(PREFIX "Bad 'n' len\n");
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
	/* Multiple chunks handling not supported. */
#define ECDSA_NR_CHUNKS 1
	context->nr_chunks = ECDSA_NR_CHUNKS;
	if (!ccc_prepare_chunks(&context->chunks[0], NULL, req,
				&context->nr_chunks))
		return NULL;

	context->data = &_pka_ecdsa_shared_data;
	data = context->data;
	memset(data, '\0', sizeof(_pka_ecdsa_shared_data));

	data->is_generation = (curve->d != NULL);
	if (data->is_generation) {
		if (!curve->k) {
			TRACE_INFO(PREFIX "'k' parameter null pointer\n");
			return NULL;
		}
		if (set_ecdsa_sign(data, req, context->chunks[0].in.addr))
			return NULL;
	} else {
		if (!curve->q) {
			TRACE_INFO(PREFIX "'q' parameter null pointer\n");
			return NULL;
		}
		if (!curve->r) {
			TRACE_INFO(PREFIX "'r' parameter null pointer\n");
			return NULL;
		}
		if (!curve->s) {
			TRACE_INFO(PREFIX "'s' parameter null pointer\n");
			return NULL;
		}
		if (set_ecdsa_verify(data, req, context->chunks[0].in.addr))
			return NULL;
	}

	return context;
}

#define ECDSA_OPCODE_SET 0x14
#define ECDSA_SIGN 0x8
#define ECDSA_VERIFY 0xC
#define OP_ID_ECDSA_SHIFT 17
static struct operation ecdsa_get_opcode(int index, unsigned char code,
					 unsigned int nr_param, ...)
{
	struct operation op;
	va_list params;

	op.code = ECDSA_OPCODE_SET << OP_ID_SHIFT;
	switch (code) {
	case ECDSA_SIGN:
		ASSERT(nr_param == 2);
		op.code |= code << OP_ID_ECDSA_SHIFT;
		op.wn = 2;
		va_start(params, nr_param);
		op.code |= va_arg(params, unsigned int) << COUNTERMEASURE_SHIFT;
		op.code |= va_arg(params, unsigned int) << LENGTH_SHIFT;
		va_end(params);
		break;
	case ECDSA_VERIFY:
		ASSERT(nr_param == 2);
		op.code |= code << OP_ID_ECDSA_SHIFT;
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

void ecdsa_program(struct pka_context *context)
{
	struct ccc_channel *channel = &context->channel;
	struct ccc_dispatcher *dispatcher = context->dispatcher;
	struct operation op;
	struct pka_shared_data *data = context->data;

	if (data->is_generation) {
		op = ecdsa_get_opcode(channel->index, ECDSA_SIGN, 2,
				      PKA_POWER_ANALYSIS_COUNTERMEASURE,
				      ECDSA_SIGN_SIZE(data));
		ccc_program(dispatcher, op.code, op.wn,
			    &data->ecdsa_sign,
			    &data->output[0]);
	} else {
		op = ecdsa_get_opcode(channel->index, ECDSA_VERIFY, 2,
				      PKA_POWER_ANALYSIS_COUNTERMEASURE,
				      ECDSA_VERIFY_SIZE(data));
		ccc_program(dispatcher, op.code, op.wn,
			    &data->ecdsa_verify,
			    &data->output[0]);
	}
}

#define NO_FAULT 0x0
int ecdsa_post_process(struct pka_context *context)
{
	struct pka_shared_data *data = context->data;
	char *output = &data->output[0];

	if (data->is_generation) {
		struct ccc_chunk *chunk = &context->chunks[0];
		struct ecdsa_signature *signature =
			(struct ecdsa_signature *)output;

		if (signature->fault != NO_FAULT) {
			TRACE_INFO(PREFIX "Fault reported: %08x\n",
				   signature->fault);
			return -EFAULT;
		}
		/* Skip error fault value before copy. */
		output += sizeof(signature->fault);
		/* Give signature only in case of success. */
		ASSERT(chunk->out.size == ECDSA_SIGNATURE_SIZE(data));
		memcpy(chunk->out.addr, output, ECDSA_SIGNATURE_SIZE(data));
	} else {
		struct ecdsa_verification *verification =
			(struct ecdsa_verification *)output;

		if (verification->fault != NO_FAULT) {
			TRACE_INFO(PREFIX "Fault reported: %08x\n",
				   verification->fault);
			return -EFAULT;
		}
	}
	return 0;
}

struct pka_alg pka_ecdsa_alg = {
	.crypto_init = ecdsa_crypto_init,
	.program = ecdsa_program,
	.post_process = ecdsa_post_process
};
