/**
 * @file sta_cot.h
 * @brief This file provides the Chain Of Trust header
 *
 * Copyright (C) ST-Microelectronics SA 2018
 * @author: ADG-MID team
 */

#ifndef _STA_COT_H_
#define _STA_COT_H_

/**
 * @brief	Init the Chain of Trust
 * @return	0 if no error, not 0 otherwise
 */
int cot_init(struct sta *context, bool ehsm_present);

#endif /* _STA_COT_H_ */
