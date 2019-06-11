/**
 * @file sta_pka.c
 * @brief CCC pka driver header.
 *
 * Copyright (C) ST-Microelectronics SA 2018
 * @author: ADG-MID team
 */

#define DEV_NAME "pka"

/* RSA / ECC configurations. */
#define NO_COUNTERMEASURE 0
#define AGAINST_SPA 1
#define AGAINST_DPA 2

#define MONTY_PAR 0x11
#define OP_ID_SHIFT 23
#define COUNTERMEASURE_SHIFT 21
#define LENGTH_SHIFT 0

struct pka_context {
	struct ccc_channel channel;
	struct ccc_dispatcher *dispatcher;
	struct pka_shared_data *data;
	bool hash;
	struct pka_alg *alg;
	struct ccc_chunk chunks[MAX(RSA_NR_CHUNKS, ECC_NR_CHUNKS)];
	unsigned int nr_chunks;
};

struct pka_alg {
	void *(*crypto_init)(struct ccc_crypto_req *req,
			     struct pka_context *context);
	void (*program_prolog)(struct pka_context *context);
	void (*program)(struct pka_context *context);
	void (*program_epilog)(struct pka_context *context);
	int (*post_process)(struct pka_context *context);
};

extern struct pka_alg pka_rsa_alg;
extern struct pka_alg pka_ecc_alg;
extern struct pka_alg pka_ecdsa_alg;

unsigned int get_dimension(unsigned char *buf, unsigned int size);
unsigned int size_in_bytes(unsigned int size);
unsigned char *word_padd(unsigned char *bignum, unsigned int size);
int append_bignum(unsigned char **buf, unsigned char *bignum,
		  unsigned int size, unsigned int *actual_size);
struct operation get_opcode(int index, unsigned char code,
			    unsigned int nr_param, ...);

#define MAX_ECC_OP_LEN DIV_ROUND_UP(MAX_ECC_SIZE_IN_BITS, 8)

static inline bool ecc_check_modulus_size(unsigned int size)
{
	if (size > MAX_ECC_OP_LEN)
		return false;
	if (size <= sizeof(unsigned int))
		return false;
	return true;
}

static inline bool ecc_check_scalar_size(unsigned int size)
{
	if (size > MAX_ECC_OP_LEN)
		return false;
	return true;
}
