/*
 * pt.h is a single-file library for processing Intel PT trace.
 * Specifically, it can
 *   (1) decode Intel PT packets: pt_get_packet(buf, size, &len)
 *       buf: a pointer to the trace buffer
 *       size: the size of the trace buffer
 *       &len: the size of the decoded trace packet
 *       @ret: the type of the decoded trace packet
 *   (2) recover control flows: pt_recover(buf, size, arg)
 *       buf: a pointer to the trace buffer
 *       size: the size of the trace buffer
 *       arg: a general arg to connect the caller specified
 *            context to the callbacks (see below)
 *       @ret: void
 *
 * It is designed to be source-based for maximum performance.
 * To recover the control flow, it depends on the pre-defined
 * interfaces for finding, understanding and following basic
 * blocks:
 *   - bool pt_block_is_call(block)
 *   - bool pt_block_is_icall(block)
 *   - bool pt_block_is_direct(block)
 *   - bool pt_block_is_ret(block)
 *   - bool pt_block_is_cond(block)
 *   - bool pt_block_is_syscall(block)
 *   - pt_block *pt_get_block(addr)
 *   - bool pt_in_block(addr, block)
 *   - unsigned long pt_get_fallthrough_addr(block)
 *   - pt_block *pt_get_fallthrough_block(block)
 *   - unsigned long pt_get_target_addr(block)
 *   - pt_block *pt_get_target_block(block)
 *
 * It also provides a default implementation of the above
 * interfaces using mirror pages when macro PT_USE_MIRROR
 * is defined when including this file.
 * The default version relies on pre-defined interfaces to
 * identifiy code page and mirror page given an address in
 * the Intel PT trace buffer:
 *   - unsigned long PT_IP_TO_CODE(unsigned long)
 *   - unsigned long PT_IP_TO_BLOCK(unsigned long)
 *   - unsigned long PT_CODE_TO_BLOCK(unsigned long)
 *   - unsigned long PT_CODE_TO_IP(unsigned long)
 *   - unsigned long PT_BLOCK_TO_CODE(unsigned long)
 *   - unsigned long PT_BLOCK_TO_IP(unsigned long)
 *
 * The default implementation used distorm, which is full of
 * bugs, so I replaced it with xed, which is maintained by
 * Intel and thus way more robust. See pt_disasm_block().
 *
 * It provides callbacks while recovering control flows:
 *   - void pt_on_block(addr, arg)
 *   - void pt_on_call(addr, arg)
 *   - void pt_on_icall(addr, arg)
 *   - void pt_on_ret(addr, arg)
 *   - void pt_on_xabort(arg)
 *   - void pt_on_xbegin(arg)
 *   - void pt_on_xcommit(arg)
 *   - void pt_on_mode(payload, arg)
 */

#ifndef _PT_H
#define _PT_H

#ifdef PT_USE_MIRROR

enum pt_block_kind {
	PT_BLOCK_DIRECT_CALL,
	PT_BLOCK_INDIRECT_CALL,
	PT_BLOCK_DIRECT_JMP,
	PT_BLOCK_INDIRECT_JMP,
	PT_BLOCK_COND_JMP,
	PT_BLOCK_RET,
	PT_BLOCK_SYSCALL,
	PT_BLOCK_TRAP,
};

typedef struct _pt_block {
	unsigned long fallthrough_addr;
	struct _pt_block *fallthrough_block;
	unsigned long target_addr;
	struct _pt_block *target_block;
	enum pt_block_kind kind;
} pt_block;

/* pt.h uses xed library for disassembling */

#include "xed/xed-interface.h"
#include <stdlib.h>
#include <string.h>

static int xed_initialized = 0;

static inline pt_block *pt_disasm_block(unsigned long addr)
{
	unsigned long curr_addr;
	pt_block *block;
	xed_decoded_inst_t xedd;
	unsigned int inst_len;
	xed_category_enum_t category;
	unsigned int num_ops;
	xed_operand_enum_t op_name;

	if (!xed_initialized) {
		xed_tables_init();
		xed_initialized = 1;
	}

	block = (pt_block *) malloc(sizeof(pt_block));
	memset((void *) block, 0, sizeof(pt_block));

	curr_addr = addr;
	while (1) {
		xed_decoded_inst_zero(&xedd);
		xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
		// 15 is the longest x86_64 instruction
		xed_decode(&xedd, (xed_uint8_t *) PT_IP_TO_CODE(curr_addr), 15);

		const xed_inst_t* xi = xed_decoded_inst_inst(&xedd);
		category = xed_decoded_inst_get_category(&xedd);
		inst_len = xed_decoded_inst_get_length(&xedd);

		switch (category) {
		case XED_CATEGORY_CALL:
			op_name = xed_operand_name(xed_inst_operand(xi, 0)); // 1st operand
			block->kind = op_name == XED_OPERAND_RELBR? PT_BLOCK_DIRECT_CALL: PT_BLOCK_INDIRECT_CALL;
			block->fallthrough_addr = curr_addr + inst_len;
			if (block->kind == PT_BLOCK_DIRECT_CALL) {
				block->target_addr = block->fallthrough_addr + xed_decoded_inst_get_branch_displacement(&xedd);
			}
			return block;
		case XED_CATEGORY_RET:
			block->kind = PT_BLOCK_RET;
			block->fallthrough_addr = curr_addr + inst_len;
			return block;
		case XED_CATEGORY_SYSCALL:
			block->kind = PT_BLOCK_SYSCALL;
			block->fallthrough_addr = curr_addr + inst_len;
			return block;
		case XED_CATEGORY_UNCOND_BR:
			num_ops = xed_decoded_inst_noperands(&xedd);
			if (num_ops > 0) {
				op_name = xed_operand_name(xed_inst_operand(xi, 0)); // 1st operand
				block->kind = op_name == XED_OPERAND_RELBR? PT_BLOCK_DIRECT_JMP: PT_BLOCK_INDIRECT_JMP;
			} else {
				block->kind = PT_BLOCK_INDIRECT_JMP;
			}
			block->fallthrough_addr = curr_addr + inst_len;
			if (block->kind == PT_BLOCK_DIRECT_JMP)
				block->target_addr = block->fallthrough_addr + xed_decoded_inst_get_branch_displacement(&xedd);
			return block;
		case XED_CATEGORY_COND_BR:
			block->kind = PT_BLOCK_COND_JMP;
			block->fallthrough_addr = curr_addr + inst_len;
			block->target_addr = block->fallthrough_addr + xed_decoded_inst_get_branch_displacement(&xedd);
			return block;
		case XED_CATEGORY_INTERRUPT:
			block->kind = PT_BLOCK_TRAP;
			block->fallthrough_addr = curr_addr + inst_len;
			return block;
		default:
			curr_addr += inst_len; // next instruction
		}
	}
}

static inline pt_block *pt_get_block(unsigned long addr)
{
	pt_block *block = *(pt_block **) PT_IP_TO_BLOCK(addr);

	if (!block) {
		block = pt_disasm_block(addr);
		*(pt_block **) PT_IP_TO_BLOCK(addr) = block;
	}

	return block;
}

#define pt_in_block(a, b) (pt_get_block(a)->fallthrough_addr == (b)->fallthrough_addr)

#define pt_get_fallthrough_addr(b) (b)->fallthrough_addr

static inline pt_block *
pt_get_fallthrough_block(pt_block *block)
{
	if (!block->fallthrough_block)
		block->fallthrough_block = pt_get_block(pt_get_fallthrough_addr(block));
	return block->fallthrough_block;
}

#define pt_get_target_addr(b) (b)->target_addr

static inline pt_block *
pt_get_target_block(pt_block *block)
{
	if (!block->target_block)
		block->target_block = pt_get_block(pt_get_target_addr(block));
	return block->target_block;
}

#define pt_block_is_call(b) ((b)->kind == PT_BLOCK_DIRECT_CALL || (b)->kind == PT_BLOCK_INDIRECT_CALL)

#define pt_block_is_icall(b) ((b)->kind == PT_BLOCK_INDIRECT_CALL)

#define pt_block_is_ret(b) ((b)->kind == PT_BLOCK_RET)

#define pt_block_is_direct(b) ((b)->kind == PT_BLOCK_DIRECT_CALL || (b)->kind == PT_BLOCK_DIRECT_JMP)

#define pt_block_is_cond(b) ((b)->kind == PT_BLOCK_COND_JMP)

#define pt_block_is_syscall(b) ((b)->kind == PT_BLOCK_SYSCALL)

#endif /* PT_USE_MIRROR */

enum pt_packet_kind {
	PT_PACKET_ERROR = -1,
	PT_PACKET_NONE,
	PT_PACKET_TNTSHORT,
	PT_PACKET_TNTLONG,
	PT_PACKET_TIP,
	PT_PACKET_TIPPGE,
	PT_PACKET_TIPPGD,
	PT_PACKET_FUP,
	PT_PACKET_PIP,
	PT_PACKET_MODE,
	PT_PACKET_TRACESTOP,
	PT_PACKET_CBR,
	PT_PACKET_TSC,
	PT_PACKET_MTC,
	PT_PACKET_TMA,
	PT_PACKET_CYC,
	PT_PACKET_VMCS,
	PT_PACKET_OVF,
	PT_PACKET_PSB,
	PT_PACKET_PSBEND,
	PT_PACKET_MNT,
	PT_PACKET_PAD,
};

static inline enum pt_packet_kind
pt_get_packet(unsigned char *buffer, unsigned long size, unsigned long *len)
{
	enum pt_packet_kind kind;
	unsigned char first_byte;
	unsigned char second_byte;
	unsigned long cyc_len;
	static unsigned long ipbytes_plus_one[8] = {1, 3, 5, 7, 7, 1, 9, 1};

	if (!buffer || !size) {
		*len = 0;
		return PT_PACKET_NONE;
	}

	first_byte = *buffer;

	if ((first_byte & 0x1) == 0) { // ???????0
		if ((first_byte & 0x2) == 0) { // ??????00
			if (first_byte == 0) {
				kind = PT_PACKET_PAD;
				*len = 1;
			} else {
				kind = PT_PACKET_TNTSHORT;
				*len = 1;
			}
		} else { // ??????10
			if (first_byte != 0x2) {
				kind = PT_PACKET_TNTSHORT;
				*len = 1;
			} else {
				if (size < 2) {
					kind = PT_PACKET_NONE;
					*len = 0;
				} else {
					second_byte = *(buffer + 1);
					if ((second_byte & 0x1) == 0) { // ???????0
						if ((second_byte & 0x2) == 0) { // ??????00
							if (second_byte != 0xc8)
								return PT_PACKET_ERROR;
							kind = PT_PACKET_VMCS;
							*len = 7;
						} else { // ??????10
							if (second_byte != 0x82)
								return PT_PACKET_ERROR;
							kind = PT_PACKET_PSB;
							*len = 16;
						}
					} else { // ???????1
						if ((second_byte & 0x10) == 0) { // ???0???1
							if ((second_byte & 0x20) == 0) { // ??00???1
								if ((second_byte & 0x40) == 0) { // ?000???1
									if ((second_byte & 0x80) == 0) { // 0000???1
										if (second_byte != 0x3)
											return PT_PACKET_ERROR;
										kind = PT_PACKET_CBR;
										*len = 4;
									} else { // 1000???1
										if (second_byte != 0x83)
											return PT_PACKET_ERROR;
										kind = PT_PACKET_TRACESTOP;
										*len = 2;
									}
								} else { // ??10???1
									if ((second_byte & 0x80) == 0) { // 0100???1
										if (second_byte != 0x43)
											return PT_PACKET_ERROR;
										kind = PT_PACKET_PIP;
										*len = 8;
									} else { // 1100???1
										if (second_byte != 0xc3)
											return PT_PACKET_ERROR;
										kind = PT_PACKET_MNT;
										*len = 11;
									}
								}
							} else { // ??10???1
								if ((second_byte & 0x80) == 0) { // 0?10???1
									if (second_byte != 0x23)
										return PT_PACKET_ERROR;
									kind = PT_PACKET_PSBEND;
									*len = 2;
								} else { // 1?10???1
									if (second_byte != 0xa3)
										return PT_PACKET_ERROR;
									kind = PT_PACKET_TNTLONG;
									*len = 8;
								}
							}
						} else { // ???1???1
							if ((second_byte & 0x80) == 0) { // 0??1???1
								if (second_byte != 0x73)
									return PT_PACKET_ERROR;
								kind = PT_PACKET_TMA;
								*len = 7;
							} else { // 1??1???1
								if (second_byte != 0xf3)
									return PT_PACKET_ERROR;
								kind = PT_PACKET_OVF;
								*len = 2;
							}
						}
					}
				}
			}
		}
	} else { // ???????1
		if ((first_byte & 0x2) == 0) { // ??????01
			if ((first_byte & 0x4) == 0) { // ?????001
				if ((first_byte & 0x8) == 0) { // ????0001
					if ((first_byte & 0x10) == 0) { // ???00001
						kind = PT_PACKET_TIPPGD;
						*len = ipbytes_plus_one[first_byte>>5];
					} else { // ???10001
						kind = PT_PACKET_TIPPGE;
						*len = ipbytes_plus_one[first_byte>>5];
					}
				} else { // ????1001
					if ((first_byte & 0x40) == 0) { // ?0??1001
						if ((first_byte & 0x80) == 0) { // 00??1001
							if (first_byte != 0x19)
								return PT_PACKET_ERROR;
							kind = PT_PACKET_TSC;
							*len = 8;
						} else { // 10??1001
							if (first_byte != 0x99)
								return PT_PACKET_ERROR;
							kind = PT_PACKET_MODE;
							*len = 2;
						}
					} else { // ?1??1001
						if (first_byte != 0x59)
							return PT_PACKET_ERROR;
						kind = PT_PACKET_MTC;
						*len = 2;
					}
				}
			} else { // ?????101
				if ((first_byte & 0x8) == 0)
					return PT_PACKET_ERROR;
				if ((first_byte & 0x10) == 0) { // ???0?101
					kind = PT_PACKET_TIP;
					*len = ipbytes_plus_one[first_byte>>5];
				} else { // ???1?101
					kind = PT_PACKET_FUP;
					*len = ipbytes_plus_one[first_byte>>5];
				}
			}
		} else { // ??????11
			if ((first_byte & 0x4) == 0) {
				kind = PT_PACKET_CYC;
				*len = 1;
			} else {
				for (cyc_len = 2; cyc_len <= size; cyc_len ++) {
					if (buffer[cyc_len-1] & 0x1) {
						cyc_len ++;
					} else {
						break;
					}
				}
				if (cyc_len > size) {
					kind = PT_PACKET_NONE;
					*len = 0;
				} else {
					kind = PT_PACKET_CYC;
					*len = cyc_len;
				}
			}
		}
	}

	return kind;
}

static inline unsigned long
pt_get_and_update_ip(unsigned char *packet, unsigned int len, unsigned long *last_ip)
{
	unsigned long ip;

	switch (len) {
	case 1:
		ip = 0;
		break;
	case 3:
		ip = ((*last_ip) & 0xffffffffffff0000) |
			*(unsigned short *)(packet+1);
		*last_ip = ip;
		break;
	case 5:
		ip = ((*last_ip) & 0xffffffff00000000) |
			*(unsigned int *)(packet+1);
		*last_ip = ip;
		break;
	case 7:
		if (((*packet) & 0x80) == 0) {
			*(unsigned int *)&ip = *(unsigned int *)(packet+1);
			*((int *)&ip+1) = (int)*(short *)(packet+5);
		} else {
			*(unsigned int *)&ip = *(unsigned int *)(packet+1);
			*((unsigned int *)&ip+1) = ((unsigned int)
					*((unsigned short *)last_ip+3) << 16 |
					(unsigned int)*(unsigned short *)(packet+5));
		}
		*last_ip = ip;
		break;
	case 9:
		ip = *(unsigned long *)(packet+1);
		*last_ip = ip;
		break;
	default:
		ip = 0;
		*last_ip = 0;
		break;
	}

	return ip;
}

static inline void
pt_recover(char *buffer, unsigned int size, pt_recover_arg arg)
{
	unsigned long bytes_remained;
	enum pt_packet_kind kind;
	unsigned char *packet;
	unsigned long packet_len;
	unsigned long last_ip = 0;
	unsigned long curr_addr = 0;
	unsigned char mask;
	unsigned char bit_selector;
	pt_block *curr_block = NULL;
#define RETC_STACK_SIZE 64
	pt_block *retc[RETC_STACK_SIZE] = {0};
	unsigned int retc_index = 0;
	unsigned char mode_payload;

#define NEXT_PACKET() \
do { \
	bytes_remained -= packet_len; \
	packet += packet_len; \
	kind = pt_get_packet(packet, bytes_remained, &packet_len); \
} while (0)

#define FOLLOW_DIRECT_UNTIL(cond) \
do { \
	while (pt_block_is_direct(curr_block) && (!(cond))) { \
		if (pt_block_is_call(curr_block)) { \
			pt_on_call(pt_get_fallthrough_addr(curr_block), arg); \
			if (pt_block_is_icall(curr_block)) \
				pt_on_icall(pt_get_fallthrough_addr(curr_block), arg); \
			retc[retc_index] = curr_block; \
			retc_index = (retc_index + 1) % RETC_STACK_SIZE; \
		} \
		pt_on_block(pt_get_target_addr(curr_block), arg); \
		curr_block = pt_get_target_block(curr_block); \
		if pt_block_is_syscall(curr_block) \
			pt_on_syscall(pt_get_fallthrough_addr(curr_block)); \
	} \
} while(0)

#define FOLLOW_DIRECT() FOLLOW_DIRECT_UNTIL(0)

	packet = buffer;
	bytes_remained = size;

	while (bytes_remained > 0) {
		kind = pt_get_packet(packet, bytes_remained, &packet_len);

		switch (kind) {
		case PT_PACKET_TNTSHORT:
			mask = (unsigned char)*packet;
			bit_selector = 1 << ((32 - __builtin_clz(mask)) - 1);
			do {
				FOLLOW_DIRECT();
				if (mask & (bit_selector >>= 1)) {
					if (pt_block_is_ret(curr_block)) {
						retc_index = (retc_index + RETC_STACK_SIZE - 1) % RETC_STACK_SIZE;
						pt_on_ret(pt_get_fallthrough_addr(retc[retc_index]), arg);
						pt_on_block(pt_get_fallthrough_addr(retc[retc_index]), arg);
						curr_block = pt_get_fallthrough_block(retc[retc_index]);
						if pt_block_is_syscall(curr_block)
							pt_on_syscall(pt_get_fallthrough_addr(curr_block));
					} else {
						pt_on_block(pt_get_target_addr(curr_block), arg);
						curr_block = pt_get_target_block(curr_block);
						if pt_block_is_syscall(curr_block)
							pt_on_syscall(pt_get_fallthrough_addr(curr_block));
					}
				} else {
					pt_on_block(pt_get_fallthrough_addr(curr_block), arg);
					curr_block = pt_get_fallthrough_block(curr_block);
					if pt_block_is_syscall(curr_block)
						pt_on_syscall(pt_get_fallthrough_addr(curr_block));
				}
			} while (bit_selector != 2);
			break;

		case PT_PACKET_TIP:
			curr_addr = pt_get_and_update_ip(packet, packet_len, &last_ip);

			if (curr_block) {
				FOLLOW_DIRECT();

				if (pt_block_is_call(curr_block)) {
					pt_on_call(pt_get_fallthrough_addr(curr_block), arg);
					if (pt_block_is_icall(curr_block))
						pt_on_icall(pt_get_fallthrough_addr(curr_block), arg);
					retc[retc_index] = curr_block;
					retc_index = (retc_index + 1) % RETC_STACK_SIZE;
				} else if (pt_block_is_ret(curr_block)) {
					pt_on_ret(curr_addr, arg);
				}
			}

			pt_on_block(curr_addr, arg);
			curr_block = pt_get_block(curr_addr);
			if pt_block_is_syscall(curr_block)
				pt_on_syscall(pt_get_fallthrough_addr(curr_block));
			break;

		case PT_PACKET_TIPPGE:
			curr_addr = pt_get_and_update_ip(packet, packet_len, &last_ip);
			curr_block = pt_get_block(curr_addr);
			break;

		case PT_PACKET_TIPPGD:
			if (curr_block)
				FOLLOW_DIRECT();
			pt_get_and_update_ip(packet, packet_len, &last_ip);
			break;

		case PT_PACKET_FUP:
			curr_addr = pt_get_and_update_ip(packet, packet_len, &last_ip);
			FOLLOW_DIRECT_UNTIL(pt_in_block(curr_addr, curr_block));
			curr_block = NULL;
			break;

		case PT_PACKET_PSB:
			last_ip = 0;
			do {
				NEXT_PACKET();
				if (kind == PT_PACKET_FUP)
					pt_get_and_update_ip(packet, packet_len, &last_ip);
			} while (kind != PT_PACKET_PSBEND && kind != PT_PACKET_OVF);
			break;

		case PT_PACKET_MODE:
			mode_payload = *(packet+1);
			switch ((mode_payload >> 5)) {
			case 0: /* MODE.Exec */
				pt_on_mode(mode_payload, arg);
				break;
			case 1: /* MODE.TSX */
				do {
					NEXT_PACKET();
				} while (kind != PT_PACKET_FUP);
				curr_addr = pt_get_and_update_ip(packet, packet_len, &last_ip);
				FOLLOW_DIRECT_UNTIL(pt_in_block(curr_addr, curr_block));

				switch ((mode_payload & (unsigned char)0x3)) {
				case 0:
					pt_on_xcommit(arg);
					break;
				case 1:
					pt_on_xbegin(arg);
					break;
				case 2:
					pt_on_xabort(arg);
					curr_block = NULL;
					break;
				default:
					break;
				}
				break;
			default:
				break;
			}
			break;

		case PT_PACKET_OVF:
			do {
				NEXT_PACKET();
			} while (kind != PT_PACKET_FUP);
			curr_addr = pt_get_and_update_ip(packet, packet_len, &last_ip);
			curr_block = pt_get_block(curr_addr);
			break;

		default:
			break;
		}

		bytes_remained -= packet_len;
		packet += packet_len;
	}
}

#endif
