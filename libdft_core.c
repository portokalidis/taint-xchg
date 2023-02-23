/*-
 * Copyright (c) 2010, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in June 2010.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * 09/10/2010:
 * 	r2r_xfer_oplb() was erroneously invoked without a third argument in
 *	MOVSX and MOVZX; proposed fix by Kangkook Jee (jikk@cs.columbia.edu)
 */

/*
 * TODO:
 * 	- optimize rep prefixed MOVS{B, W, D}
 */

#include <err.h>

#include "pin.H"
#include "libdft_api.h"
#include "libdft_core.h"
#include "tagmap.h"
#include "branch_pred.h"


/* threads context */
extern thread_ctx_t *threads_ctx;

/* tagmap */
extern uint8_t *bitmap;

/* 
 * REG-to-VCPU map;
 * get the register index in the VCPU structure
 * given a PIN register (32-bit regs)
 *
 * @reg:	the PIN register
 * returns:	the index of the register in the VCPU
 */
/* static inline */ size_t
REG32_INDX(REG reg)
{
	/* result; for the 32-bit registers the mapping is easy */
	size_t indx = reg - R32_ALIGN;
	
	/* 
	 * sanity check;
	 * unknown registers are mapped to the scratch
	 * register of the VCPU
	 */
	if (unlikely(indx > GRP_NUM))
		indx = GRP_NUM;
	
	/* return the index */
	return indx;	
}

/* 
 * REG-to-VCPU map;
 * get the register index in the VCPU structure
 * given a PIN register (16-bit regs)
 *
 * @reg:	the PIN register
 * returns:	the index of the register in the VCPU
 */
/* static inline */ size_t
REG16_INDX(REG reg)
{
	/* 
	 * differentiate based on the register;
	 * we map the 16-bit registers to their 32-bit
	 * containers (e.g., AX -> EAX)
	 */
	switch (reg) {
		/* di */
		case REG_DI:
			return 0;
			/* not reached; safety */
			break;
		/* si */
		case REG_SI:
			return 1;
			/* not reached; safety */
			break;
		/* bp */
		case REG_BP:
			return 2;
			/* not reached; safety */
			break;
		/* sp */
		case REG_SP:
			return 3;
			/* not reached; safety */
			break;
		/* bx */
		case REG_BX:
			return 4;
			/* not reached; safety */
			break;
		/* dx */
		case REG_DX:
			return 5;
			/* not reached; safety */
			break;
		/* cx */
		case REG_CX:
			return 6;
			/* not reached; safety */
			break;
		/* ax */
		case REG_AX:
			return 7;
			/* not reached; safety */
			break;
		default:
			/* 
			 * paranoia;
			 * unknown 16-bit registers are mapped
			 * to the scratch register of the VCPU
			 */
			return 8;
	}
}

/* 
 * REG-to-VCPU map;
 * get the register index in the VCPU structure
 * given a PIN register (8-bit regs)
 *
 * @reg:	the PIN register
 * returns:	the index of the register in the VCPU
 */
/* static inline */ size_t
REG8_INDX(REG reg)
{
	/* 
	 * differentiate based on the register;
	 * we map the 8-bit registers to their 32-bit
	 * containers (e.g., AH -> EAX)
	 */
	switch (reg) {
		/* ah/al */
		case REG_AH:
		case REG_AL:
			return 7;
			/* not reached; safety */
			break;
		/* ch/cl */
		case REG_CH:
		case REG_CL:
			return 6;
			/* not reached; safety */
			break;
		/* dh/dl */
		case REG_DH:
		case REG_DL:
			return 5;
			/* not reached; safety */
			break;
		/* bh/bl */
		case REG_BH:
		case REG_BL:
			return 4;
			/* not reached; safety */
			break;
		default:
			/* 
			 * paranoia;
			 * unknown 8-bit registers are mapped
			 * to the scratch register
			 */
			return 8;
	}
}

/*
 * tag propagation (analysis function)
 *
 * extend the tag as follows: t[eax] = t[ax];
 * special case for the cwde instruction
 *
 * @tid:	the thread id
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_ext_oplw(THREADID tid)
{
	threads_ctx[tid].vcpu.gpr[7] =
		((threads_ctx[tid].vcpu.gpr[7] << 2) |
		(threads_ctx[tid].vcpu.gpr[7] & VCPU_MASK16))
		& VCPU_MASK32;
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag among three 8-bit 
 * registers as t[dst] |= (t[upper(dst)] | t[lower(dst)] | t[src]);
 * dst is AX, whereas src is an 8-bit register (e.g., CL, BH, ...)
 *
 * NOTE: special case for DIV and IDIV instructions
 *
 * @tid:	the thread id
 * @src:	source register index (VCPU)
 * @high:	1: the source is 8-bit high (e.g., AH), 0: all other cases 
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_ternary_opwb(THREADID tid, uint32_t src, uint32_t high)
{
	/* temporary tag value */
	size_t tmp_tag = 
		((threads_ctx[tid].vcpu.gpr[7] & VCPU_MASK8) | 
		(threads_ctx[tid].vcpu.gpr[7] & (VCPU_MASK8 << 1)) >> 1) |
		((threads_ctx[tid].vcpu.gpr[src] & (VCPU_MASK8 << high)) >>
		 high);
	
	/* extend the tag from the lower 8-bits to the upper 8-bits */
	tmp_tag |= tmp_tag << 1;

	/* update the destination (ternary) */
	threads_ctx[tid].vcpu.gpr[7] |= tmp_tag;
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag among three 8-bit 
 * registers as t[dst] |= (t[lower(dst)] | t[src]);
 * dst is AX, whereas src is an 8-bit register
 * (e.g., CL, BH, ...)
 *
 * NOTE: special case for MUL and IMUL instructions
 *
 * @tid:	the thread id
 * @src:	source register index (VCPU)
 * @high:	1: the source is 8-bit high (e.g., AH), 0: all other cases 
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_ternary_opwb2(THREADID tid, uint32_t src, uint32_t high)
{
	/* temporary tag value */
	size_t tmp_tag = 
		(threads_ctx[tid].vcpu.gpr[7] & VCPU_MASK8) | 
		((threads_ctx[tid].vcpu.gpr[src] & (VCPU_MASK8 << high)) >>
		 high);
	
	/* extend the tag from the lower 8-bits to the upper 8-bits */
	tmp_tag |= tmp_tag << 1;

	/* update the destination (ternary) */
	threads_ctx[tid].vcpu.gpr[7] =
		(threads_ctx[tid].vcpu.gpr[7] & ~VCPU_MASK16) | tmp_tag;
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * registers as t[upper(dst)] |= t[lower(src)];
 * dst and src are considered to be 8-bit
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opb_ul(THREADID tid, uint32_t dst, uint32_t src)
{
	threads_ctx[tid].vcpu.gpr[dst] |=
		(threads_ctx[tid].vcpu.gpr[src] & VCPU_MASK8) << 1;
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * registers as t[lower(dst)] |= t[upper(src)];
 * dst and src are considered to be 8-bit
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opb_lu(THREADID tid, uint32_t dst, uint32_t src)
{
	threads_ctx[tid].vcpu.gpr[dst] |=
		(threads_ctx[tid].vcpu.gpr[src] & (VCPU_MASK8 << 1)) >> 1;
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * registers as t[dst] |= t[src]
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 * @high:	1: the registers are 8-bit high (e.g., AH), 0: all other cases 
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opb(THREADID tid, uint32_t dst, uint32_t src, uint32_t high)
{
	threads_ctx[tid].vcpu.gpr[dst] |=
		threads_ctx[tid].vcpu.gpr[src] & (VCPU_MASK8 << high);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between among three 16-bit 
 * registers as t[dst1] |= (t[dst1] | t[dst2] | t[src])
 * and t[dst2] |= (t[dst1] | t[dst2] | t[src]);
 * dst1 is DX, dst2 is AX, and src is a 16-bit register 
 * (e.g., CX, BX, ...)
 *
 * NOTE: special case for DIV and IDIV instructions
 *
 * @tid:	the thread id
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_ternary_opw(THREADID tid, uint32_t src)
{
	/* temporary tag value */
	size_t tmp_tag = 
		((threads_ctx[tid].vcpu.gpr[src] & VCPU_MASK16)	|
		(threads_ctx[tid].vcpu.gpr[5] & VCPU_MASK16))|
		(threads_ctx[tid].vcpu.gpr[7] & VCPU_MASK16);
	
	/* update the destinations */
	threads_ctx[tid].vcpu.gpr[5] |= tmp_tag;
	threads_ctx[tid].vcpu.gpr[7] |= tmp_tag;
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between among three 16-bit 
 * registers as t[dst1] |= (t[dst2] | t[src]) and
 * t[dst2] |= t[src]; dst1 is DX, dst2 is AX, and
 * src is a 16-bit register (e.g., CX, BX, ...)
 *
 * NOTE: special case for MUL and IMUL instructions
 *
 * @tid:	the thread id
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_ternary_opw2(THREADID tid, uint32_t src)
{
	/* temporary tag value */
	size_t tmp_tag = 
		(threads_ctx[tid].vcpu.gpr[src] & VCPU_MASK16)	|
		(threads_ctx[tid].vcpu.gpr[7] & VCPU_MASK16);
	
	/* update the destinations */
	threads_ctx[tid].vcpu.gpr[7] |= tmp_tag;
	threads_ctx[tid].vcpu.gpr[5] =
		(threads_ctx[tid].vcpu.gpr[5] & ~VCPU_MASK16) | tmp_tag;
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 16-bit register
 * and an 8-bit one as t[dst] |= t[lower(src)];
 * src is CL
 *
 * NOTE: special case for rotate and shift
 * instructions (e.g., RCL, ROL, SHR, SAL, ...)
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opwb(THREADID tid, uint32_t dst)
{
	/* temporary tag value */
	size_t tmp_tag = 
		threads_ctx[tid].vcpu.gpr[6] & VCPU_MASK8;

	/* extend the tag from 8-bits to 16-bits */
	tmp_tag |= tmp_tag << 1;
	
	/* update the destination (binary) */	
	threads_ctx[tid].vcpu.gpr[dst] |= tmp_tag;
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 16-bit registers
 * as t[dst] |= t[src]
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opw(THREADID tid, uint32_t dst, uint32_t src)
{
	threads_ctx[tid].vcpu.gpr[dst] |=
		threads_ctx[tid].vcpu.gpr[src] & VCPU_MASK16;
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between among three 32-bit 
 * registers as t[dst1] |= (t[dst1] | t[dst2] | t[src])
 * and t[dst2] |= (t[dst1] | t[dst2] | t[src]);
 * dst1 is EDX, dst2 is EAX, and src is a 16-bit register
 * (e.g., CX, BX, ...)
 *
 * NOTE: special case for DIV and IDIV instructions
 *
 * @tid:	the thread id
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_ternary_opl(THREADID tid, uint32_t src)
{ 
	/* temporary tag value */
	size_t tmp_tag = 
		(threads_ctx[tid].vcpu.gpr[5] |
		threads_ctx[tid].vcpu.gpr[7]) |
		threads_ctx[tid].vcpu.gpr[src];

	/* update the destinations */
	threads_ctx[tid].vcpu.gpr[5] |= tmp_tag;
	threads_ctx[tid].vcpu.gpr[7] |= tmp_tag;
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between among three 32-bit 
 * registers as t[dst1] |= (t[dst1] | t[dst2] | t[src])
 * and t[dst2] |= (t[dst1] | t[dst2] | t[src]);
 * dst1 is EDX, dst2 is EAX, and src is a 32-bit register
 * (e.g., CX, BX, ...)
 *
 * NOTE: special case for MUL and IMUL instructions
 *
 * @tid:	the thread id
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_ternary_opl2(THREADID tid, uint32_t src)
{
	/* temporary tag value */
	size_t tmp_tag = 
		threads_ctx[tid].vcpu.gpr[7] |
		threads_ctx[tid].vcpu.gpr[src];

	/* update the destinations */
	threads_ctx[tid].vcpu.gpr[7] |= tmp_tag;
	threads_ctx[tid].vcpu.gpr[5] = tmp_tag;
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 32-bit register
 * and an 8-bit as t[dst] |= t[lower(src)];
 * src is CL
 *
 * NOTE: special case for rotate and shift
 * instructions (e.g., RCL, ROL, SHR, SAL, ...)
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_binary_oplb(THREADID tid, uint32_t dst)
{
	/* temporary tag value */
	size_t tmp_tag = 
		threads_ctx[tid].vcpu.gpr[6] & VCPU_MASK8;

	/* extend the tag from 8-bits to 32-bits */
	tmp_tag |= (tmp_tag << 1);
	tmp_tag |= (tmp_tag << 2);
	
	/* update the destination (binary) */	
	threads_ctx[tid].vcpu.gpr[dst] |= tmp_tag;
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 32-bit 
 * registers as t[dst] |= t[src]
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opl(THREADID tid, uint32_t dst, uint32_t src)
{
	threads_ctx[tid].vcpu.gpr[dst] |=
		threads_ctx[tid].vcpu.gpr[src];
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag among two 8-bit registers
 * and an 8-bit memory location as
 * t[dst] |= (t[upper(dst)] | t[lower(dst)] | t[src]);
 * dst is AX, whereas src is an 8-bit memory location
 *
 * NOTE: special case for DIV and IDIV instructions
 *
 * @tid:	the thread id
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_ternary_opwb(THREADID tid, ADDRINT src)
{
	/* temporary tag value */
	size_t tmp_tag = 
		((threads_ctx[tid].vcpu.gpr[7] & VCPU_MASK8) | 
		(threads_ctx[tid].vcpu.gpr[7] & (VCPU_MASK8 << 1)) >> 1) |
		((bitmap[VIRT2BYTE(src)] >> VIRT2BIT(src)) & VCPU_MASK8);
	
	/* extend the tag from the lower 8-bits to the upper 8-bits */
	tmp_tag |= tmp_tag << 1;

	/* update the destination (ternary) */
	threads_ctx[tid].vcpu.gpr[7] |= tmp_tag;
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag among two 8-bit registers
 * and an 8-bit memory location as
 * t[upper(dst)] = t[lower(dst)] | t[src] and
 * t[lower(dst] |= t[src]; dst is AX, whereas
 * src is an 8-bit memory location
 *
 * @tid:	the thread id
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_ternary_opwb2(THREADID tid, ADDRINT src)
{
	/* temporary tag value */
	size_t tmp_tag = 
		(threads_ctx[tid].vcpu.gpr[7] & VCPU_MASK8) | 
		((bitmap[VIRT2BYTE(src)] >> VIRT2BIT(src)) & VCPU_MASK8);
	
	/* extend the tag from the lower 8-bits to the upper 8-bits */
	tmp_tag |= tmp_tag << 1;

	/* update the destination (ternary) */
	threads_ctx[tid].vcpu.gpr[7] = 
		(threads_ctx[tid].vcpu.gpr[7] & ~VCPU_MASK16) | tmp_tag;
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between an 8-bit 
 * register and a memory location as
 * t[dst] |= t[src] (dst is a register)
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 * @high:	1: the register is 8-bit high (e.g., AH), 0: all other cases
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_binary_opb(THREADID tid, uint32_t dst, ADDRINT src, uint32_t high)
{
	threads_ctx[tid].vcpu.gpr[dst] |=
		(bitmap[VIRT2BYTE(src)] >> (VIRT2BIT(src) - high)) & 
		(VCPU_MASK8 << high);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag among two 16-bit registers
 * and a 16-bit memory address as
 * t[dst1] |= (t[dst1] | t[dst2] | t[src]) and
 * t[dst1] |= (t[dst1] | t[dst2] | t[src]);
 *
 * dst1 is DX, dst2 is AX, and src is a 16-bit
 * memory location
 *
 * NOTE: special case for DIV and IDIV instructions
 *
 * @tid:	the thread id
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_ternary_opw(THREADID tid, ADDRINT src)
{
	/* temporary tag value */
	size_t tmp_tag = 
		(((*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		 VCPU_MASK16) |
		(threads_ctx[tid].vcpu.gpr[5] & VCPU_MASK16)) |
		(threads_ctx[tid].vcpu.gpr[7] & VCPU_MASK16);
	
	/* update the destinations */
	threads_ctx[tid].vcpu.gpr[5] |= tmp_tag; 
	threads_ctx[tid].vcpu.gpr[7] |= tmp_tag; 
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag among two 16-bit registers
 * and a 16-bit memory address as
 * t[dst1] |= (t[dst2] | t[src]) and
 * t[dst2] |= t[src]; dst1 is DX, dst2 is
 * AX, and src is a 16-bit memory location
 *
 * NOTE: special case for MUL and IMUL instructions
 *
 * @tid:	the thread id
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_ternary_opw2(THREADID tid, ADDRINT src)
{
	/* temporary tag value */
	size_t tmp_tag = 
		((*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		 VCPU_MASK16) |
		(threads_ctx[tid].vcpu.gpr[7] & VCPU_MASK16);
	
	/* update the destinations */
	threads_ctx[tid].vcpu.gpr[7] |= tmp_tag; 
	threads_ctx[tid].vcpu.gpr[5] =
		(threads_ctx[tid].vcpu.gpr[5] & ~VCPU_MASK16) | tmp_tag; 
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 16-bit 
 * register and a memory location as
 * t[dst] |= t[src] (dst is a register)
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_binary_opw(THREADID tid, uint32_t dst, ADDRINT src)
{
	threads_ctx[tid].vcpu.gpr[dst] |=
		(*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK16;
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag among two 32-bit 
 * registers and a 32-bit memory as
 * t[dst1] |= (t[dst1] | t[dst2] | t[src])
 * and t[dst2] |= (t[dst1] | t[dst2] | t[src]);
 * dst1 is EDX, dst2 is EAX, and src is a 32-bit
 * memory location
 *
 * NOTE: special case for DIV and IDIV instructions
 *
 * @tid:	the thread id
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_ternary_opl(THREADID tid, ADDRINT src)
{
	/* temporary tag value */
	size_t tmp_tag = 
		(((*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK32) |
		threads_ctx[tid].vcpu.gpr[5]) | 
		threads_ctx[tid].vcpu.gpr[7];

	/* update the destinations */
	threads_ctx[tid].vcpu.gpr[5] |= tmp_tag;
	threads_ctx[tid].vcpu.gpr[7] |= tmp_tag;
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag among two 32-bit 
 * registers and a 32-bit memory as
 * t[dst1] = (t[dst2] | t[src]) and
 * t[dst2] |= t[src];
 *
 * dst1 is EDX, dst2 is EAX, and src is
 * a 32-bit memory location
 *
 * NOTE: special case for MUL and IMUL instructions
 *
 * @tid:	the thread id
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_ternary_opl2(THREADID tid, ADDRINT src)
{
	/* temporary tag value */
	size_t tmp_tag = 
		((*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK32) |
		threads_ctx[tid].vcpu.gpr[7];

	/* update the destinations */
	threads_ctx[tid].vcpu.gpr[7] |= tmp_tag;
	threads_ctx[tid].vcpu.gpr[5] = tmp_tag;
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 32-bit 
 * register and a memory location as
 * t[dst] |= t[src] (dst is a register)
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_binary_opl(THREADID tid, uint32_t dst, ADDRINT src)
{
	threads_ctx[tid].vcpu.gpr[dst] |=
		(*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK32;
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between an 8-bit 
 * register and a memory location as
 * t[dst] |= t[src] (src is a register)
 *
 * @tid:	the thread id
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 * @high:	1: the register is 8-bit high (e.g., AH), 0: all other cases
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_binary_opb(THREADID tid, ADDRINT dst, uint32_t src, uint32_t high)
{
	bitmap[VIRT2BYTE(dst)] |=
		((threads_ctx[tid].vcpu.gpr[src] & (VCPU_MASK8 << high)) >>
		high) << VIRT2BIT(dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between an 8-bit 
 * register and a 16-bit memory location as
 * t[dst] |= t[lower(src)]; src is CL
 *
 * NOTE: special case for rotate and shift
 * instructions (e.g., RCL, ROL, SHR, SAL, ...)
 *
 * @tid:	the thread id
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_binary_opwb(THREADID tid, ADDRINT dst)
{
	/* temporary tag */
	size_t tmp_tag =  threads_ctx[tid].vcpu.gpr[6] & VCPU_MASK8;
	
	/* extend the tag from 8-bits to 16-bits */
	tmp_tag |= (tmp_tag << 1);
	
	/* update the destination (binary) */	
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) |=
		(((uint16_t)tmp_tag) << VIRT2BIT(dst));
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 16-bit 
 * register and a memory location as
 * t[dst] |= t[src] (src is a register)
 *
 * @tid:	the thread id
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_binary_opw(THREADID tid, ADDRINT dst, uint32_t src)
{
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) |=
		((uint16_t)(threads_ctx[tid].vcpu.gpr[src] & VCPU_MASK16)) <<
		VIRT2BIT(dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between an 8-bit 
 * register and a 32-bit memory location as
 * t[dst] |= t[lower(src)]; src is CL
 *
 * NOTE: special case for rotate and shift
 * instructions (e.g., RCL, ROL, SHR, SAL, ...)
 *
 * @tid:	the thread id
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_binary_oplb(THREADID tid, ADDRINT dst, uint32_t src)
{
	/* temporary tag */
	size_t tmp_tag =  threads_ctx[tid].vcpu.gpr[6] & VCPU_MASK8;
	
	/* extend the tag from 8-bits to 32-bits */
	tmp_tag |= (tmp_tag << 1);
	tmp_tag |= (tmp_tag << 2);
	
	/* update the destination (binary) */	
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) |=
		(((uint16_t)tmp_tag) << VIRT2BIT(dst));
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 32-bit 
 * register and a memory location as
 * t[dst] |= t[src] (src is a register)
 *
 * @tid:	the thread id
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_binary_opl(THREADID tid, ADDRINT dst, uint32_t src)
{
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) |=
		((uint16_t)(threads_ctx[tid].vcpu.gpr[src] & VCPU_MASK32)) <<
		VIRT2BIT(dst);
}

/*
 * tag propagation (analysis function)
 *
 * clear the tag of EAX, EBX, ECX, EDX
 *
 * @tid:	the thread id
 * @reg:	register index (VCPU) 
 */
static void PIN_FAST_ANALYSIS_CALL
r_clrl4(THREADID tid)
{
	threads_ctx[tid].vcpu.gpr[4] = 0;
	threads_ctx[tid].vcpu.gpr[5] = 0;
	threads_ctx[tid].vcpu.gpr[6] = 0;
	threads_ctx[tid].vcpu.gpr[7] = 0;
}

/*
 * tag propagation (analysis function)
 *
 * clear the tag of EAX, EDX
 *
 * @tid:	the thread id
 * @reg:	register index (VCPU) 
 */
static void PIN_FAST_ANALYSIS_CALL
r_clrl2(THREADID tid)
{
	threads_ctx[tid].vcpu.gpr[5] = 0;
	threads_ctx[tid].vcpu.gpr[7] = 0;
}

/*
 * tag propagation (analysis function)
 *
 * clear the tag of a 32-bit register
 *
 * @tid:	the thread id
 * @reg:	register index (VCPU) 
 */
static void PIN_FAST_ANALYSIS_CALL
r_clrl(THREADID tid, uint32_t reg)
{
	threads_ctx[tid].vcpu.gpr[reg] = 0;
}

/*
 * tag propagation (analysis function)
 *
 * clear the tag of a 16-bit register
 *
 * @tid:	the thread id
 * @reg:	register index (VCPU) 
 */
static void PIN_FAST_ANALYSIS_CALL
r_clrw(THREADID tid, uint32_t reg)
{
	threads_ctx[tid].vcpu.gpr[reg] &= ~VCPU_MASK16;
}

/*
 * tag propagation (analysis function)
 *
 * clear the tag of an 8-bit register
 *
 * @tid:	the thread id
 * @reg:	register index (VCPU) 
 * @high:	1: the register is an 8-bit high (e.g., AH), 0: all other cases 
 */
static void PIN_FAST_ANALYSIS_CALL
r_clrb(THREADID tid, uint32_t reg, uint32_t high)
{
	threads_ctx[tid].vcpu.gpr[reg] &= ~(VCPU_MASK8 << high);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * registers as t[upper(dst)] = t[lower(src)]
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opb_ul(THREADID tid, uint32_t dst, uint32_t src)
{
	threads_ctx[tid].vcpu.gpr[dst] =
	(threads_ctx[tid].vcpu.gpr[dst] & ~(VCPU_MASK8 << 1)) |
	((threads_ctx[tid].vcpu.gpr[src] & VCPU_MASK8) << 1);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * registers as t[lower(dst)] = t[upper(src)];
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opb_lu(THREADID tid, uint32_t dst, uint32_t src)
{
	threads_ctx[tid].vcpu.gpr[dst] =
		(threads_ctx[tid].vcpu.gpr[dst] & ~VCPU_MASK8) | 
		((threads_ctx[tid].vcpu.gpr[src] & (VCPU_MASK8 << 1)) >> 1);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * registers as t[dst] = t[src]
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 * @high:	1: the registers are 8-bit high (e.g., AH), 0: all other cases 
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opb(THREADID tid, uint32_t dst, uint32_t src, uint32_t high)
{
	threads_ctx[tid].vcpu.gpr[dst] =
		(threads_ctx[tid].vcpu.gpr[dst] & ~(VCPU_MASK8 << high)) |
		(threads_ctx[tid].vcpu.gpr[src] & (VCPU_MASK8 << high));
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 16-bit 
 * register and an 8-bit register as t[dst] = t[src];
 *
 * NOTE: special case for MOVSX and MOVZX instructions
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 * @high:	1: the src register is 8-bit high, 0: all other cases 
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opwb(THREADID tid, uint32_t dst, uint32_t src, uint32_t high)
{
	/* temporary tag value */
	size_t src_tag = 
		(threads_ctx[tid].vcpu.gpr[src] & (VCPU_MASK8 << high)) >> high;
	
	/* extension; 8-bit to 16-bit */
	src_tag |= (src_tag << 1);

	/* update the destination (xfer) */
	threads_ctx[tid].vcpu.gpr[dst] =
		(threads_ctx[tid].vcpu.gpr[dst] & ~VCPU_MASK16) | src_tag;
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 16-bit
 * registers as t[AX] = t[src]; return
 * the result of AX == src and also
 * store the original tag value of
 * AX in the scratch register
 *
 * @tid:	the thread id
 * @dst_val:	AX register value
 * @src:	source register index (VCPU)
 * @src_val:	source register value
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
r2r_xfer_opw_fast(THREADID tid, uint16_t dst_val, uint32_t src,
						uint16_t src_val)
{
	/* save the tag value of dst in the scratch register */
	threads_ctx[tid].vcpu.gpr[8] = 
		threads_ctx[tid].vcpu.gpr[7];
	
	/* update */
	threads_ctx[tid].vcpu.gpr[7] =
		(threads_ctx[tid].vcpu.gpr[7] & ~VCPU_MASK16) |
		(threads_ctx[tid].vcpu.gpr[src] & VCPU_MASK16);

	/* compare the dst and src values */
	return (dst_val == src_val);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 16-bit 
 * registers as t[dst] = t[src]; restore the
 * value of AX from the scratch register
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opw_slow(THREADID tid, uint32_t dst, uint32_t src)
{
	/* restore the tag value from the scratch register */
	threads_ctx[tid].vcpu.gpr[7] = 
		threads_ctx[tid].vcpu.gpr[8];
	
	/* update */
	threads_ctx[tid].vcpu.gpr[dst] =
		(threads_ctx[tid].vcpu.gpr[dst] & ~VCPU_MASK16) |
		(threads_ctx[tid].vcpu.gpr[src] & VCPU_MASK16);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 16-bit 
 * registers as t[dst] = t[src]
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opw(THREADID tid, uint32_t dst, uint32_t src)
{
	threads_ctx[tid].vcpu.gpr[dst] =
		(threads_ctx[tid].vcpu.gpr[dst] & ~VCPU_MASK16) |
		(threads_ctx[tid].vcpu.gpr[src] & VCPU_MASK16);
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 32-bit register
 * and an 8-bit register as t[dst] = t[src]
 *
 * NOTE: special case for MOVSX and MOVZX instructions
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 * @high:	1: the src register is 8-bit high, 0: all other cases 
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_oplb(THREADID tid, uint32_t dst, uint32_t src, uint32_t high)
{
	/* temporary tag value */
	size_t src_tag = 
		(threads_ctx[tid].vcpu.gpr[src] & (VCPU_MASK8 << high)) >> high;

	/* extension; 8-bit to 32-bit */
	src_tag |= (src_tag << 1);
	src_tag |= (src_tag << 2);
	
	/* update the destination (xfer) */
	threads_ctx[tid].vcpu.gpr[dst] = src_tag;
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 32-bit register
 * and a 16-bit register as t[dst] = t[src]
 *
 * NOTE: special case for MOVSX and MOVZX instructions
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_oplw(THREADID tid, uint32_t dst, uint32_t src)
{
	threads_ctx[tid].vcpu.gpr[dst] =
		(threads_ctx[tid].vcpu.gpr[src] & VCPU_MASK16) |
		((threads_ctx[tid].vcpu.gpr[src] & VCPU_MASK16) << 2);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 32-bit
 * registers as t[EAX] = t[src]; return
 * the result of EAX == src and also
 * store the original tag value of
 * EAX in the scratch register
 *
 * @tid:	the thread id
 * @dst_val:	EAX register value
 * @src:	source register index (VCPU)
 * @src_val:	source register value
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
r2r_xfer_opl_fast(THREADID tid, uint32_t dst_val, uint32_t src,
							uint32_t src_val)
{
	/* save the tag value of dst in the scratch register */
	threads_ctx[tid].vcpu.gpr[8] = 
		threads_ctx[tid].vcpu.gpr[7];
	
	/* update */
	threads_ctx[tid].vcpu.gpr[7] =
		threads_ctx[tid].vcpu.gpr[src];

	/* compare the dst and src values */
	return (dst_val == src_val);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 32-bit 
 * registers as t[dst] = t[src]; restore the
 * value of EAX from the scratch register
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opl_slow(THREADID tid, uint32_t dst, uint32_t src)
{
	/* restore the tag value from the scratch register */
	threads_ctx[tid].vcpu.gpr[7] = 
		threads_ctx[tid].vcpu.gpr[8];
	
	/* update */
	threads_ctx[tid].vcpu.gpr[dst] =
		threads_ctx[tid].vcpu.gpr[src];
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 32-bit 
 * registers as t[dst] = t[src]
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opl(THREADID tid, uint32_t dst, uint32_t src)
{
	threads_ctx[tid].vcpu.gpr[dst] =
		threads_ctx[tid].vcpu.gpr[src];
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between an 8-bit 
 * register and a memory location as
 * t[dst] = t[src] (dst is a register)
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 * @high:	1: the register is 8-bit high (e.g., AH), 0: all other cases
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opb(THREADID tid, uint32_t dst, ADDRINT src, uint32_t high)
{
	threads_ctx[tid].vcpu.gpr[dst] =
		(threads_ctx[tid].vcpu.gpr[dst] & ~(VCPU_MASK8 << high)) |
		(((bitmap[VIRT2BYTE(src)] >> VIRT2BIT(src)) << high) &
		(VCPU_MASK8 << high));
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 16-bit 
 * register and an 8-bit memory location as
 * t[dst] = t[src]
 *
 * NOTE: special case for MOVSX and MOVZX instructions
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opwb(THREADID tid, uint32_t dst, ADDRINT src)
{
	/* temporary tag value */
	size_t src_tag = 
		(bitmap[VIRT2BYTE(src)] >> VIRT2BIT(src)) & VCPU_MASK8;
	
	/* extension; 8-bit to 16-bit */
	src_tag |= (src_tag << 1);
	
	/* update the destination (xfer) */ 
	threads_ctx[tid].vcpu.gpr[dst] =
		(threads_ctx[tid].vcpu.gpr[dst] & ~VCPU_MASK16) | src_tag;
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 16-bit 
 * register and a memory location as
 * t[dst] = t[src] (dst is a register)
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opw(THREADID tid, uint32_t dst, ADDRINT src)
{
	threads_ctx[tid].vcpu.gpr[dst] =
		(threads_ctx[tid].vcpu.gpr[dst] & ~VCPU_MASK16) |
		((*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK16);
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 32-bit 
 * register and an 8-bit memory location as
 * t[dst] = t[src]
 *
 * NOTE: special case for MOVSX and MOVZX instructions
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_oplb(THREADID tid, uint32_t dst, ADDRINT src)
{
	/* temporary tag value */
	size_t src_tag = 
		(bitmap[VIRT2BYTE(src)] >> VIRT2BIT(src)) & VCPU_MASK8;
	
	/* extension; 8-bit to 32-bit */
	src_tag |= (src_tag << 1);
	src_tag |= (src_tag << 2);
	
	/* update the destination (xfer) */
	threads_ctx[tid].vcpu.gpr[dst] = src_tag;
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 32-bit register
 * and a 16-bit register as t[dst] = t[src]
 *
 * NOTE: special case for MOVSX and MOVZX instructions
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_oplw(THREADID tid, uint32_t dst, uint32_t src)
{
	/* temporary tag value */
	size_t src_tag = 
		((*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK16);

	/* extension; 16-bit to 32-bit */
	src_tag |= (src_tag << 2);
	
	/* update the destination (xfer) */
	threads_ctx[tid].vcpu.gpr[dst] = src_tag;
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 32-bit 
 * register and a memory location as
 * t[dst] = t[src] (dst is a register)
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opl(THREADID tid, uint32_t dst, ADDRINT src)
{
	threads_ctx[tid].vcpu.gpr[dst] =
		(*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK32;
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between an 8-bit 
 * register and a n-memory locations as
 * t[dst] = t[src]; src is AL
 *
 * @tid:	the thread id
 * @dst:	destination memory address
 * @high:	1: the register is 8-bit high (e.g., AH), 0: all other cases
 * @count:	memory bytes
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opbn(THREADID tid, ADDRINT dst, uint32_t count)
{
	/* the source register is taged */
	if (threads_ctx[tid].vcpu.gpr[7] & VCPU_MASK8)
		tagmap_setn(dst, count);
	/* the source register is clear */
	else
		tagmap_clrn(dst, count);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between an 8-bit 
 * register and a memory location as
 * t[dst] = t[src] (src is a register)
 *
 * @tid:	the thread id
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 * @high:	1: the register is 8-bit high (e.g., AH), 0: all other cases
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opb(THREADID tid, ADDRINT dst, uint32_t src, uint32_t high)
{
	bitmap[VIRT2BYTE(dst)] =
		(bitmap[VIRT2BYTE(dst)] & ~(BYTE_MASK << VIRT2BIT(dst))) |
		(((threads_ctx[tid].vcpu.gpr[src] & (VCPU_MASK8 << high)) >>
		high) << VIRT2BIT(dst));
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 16-bit
 * register and a memory location
 * as t[AX] = t[src]; return the result
 * of AX == src and also store the
 * original tag value of AX in
 * the scratch register
 *
 * @tid:	the thread id
 * @dst:	destination register index (VCPU)
 * @dst_val:	destination register value
 * @src:	source memory address
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
r2m_xfer_opw_fast(THREADID tid, uint16_t dst_val, ADDRINT src)
{
	/* save the tag value of dst in the scratch register */
	threads_ctx[tid].vcpu.gpr[8] = 
		threads_ctx[tid].vcpu.gpr[7];
	
	/* update */
	threads_ctx[tid].vcpu.gpr[7] =
		(threads_ctx[tid].vcpu.gpr[7] & ~VCPU_MASK16) |
		((*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK16);
	
	/* compare the dst and src values; the original values the tag bits */
	return (dst_val == *(uint16_t *)src);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 16-bit 
 * register and a n-memory locations as
 * t[dst] = t[src]; src is AX
 *
 * @tid:	the thread id
 * @dst:	destination memory address
 * @count:	memory words
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opwn(THREADID tid, ADDRINT dst, uint32_t count)
{
	/* the source register is taged */
	if (threads_ctx[tid].vcpu.gpr[7] & VCPU_MASK16)
		tagmap_setn(dst, (count << 1));
	/* the source register is clear */
	else
		tagmap_clrn(dst, (count << 1));
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 16-bit 
 * register and a memory location
 * as t[dst] = t[src]; restore the value
 * of AX from the scratch register
 *
 * @tid:	the thread id
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 * @res:	restore register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opw_slow(THREADID tid, ADDRINT dst, uint32_t src)
{
	/* restore the tag value from the scratch register */
	threads_ctx[tid].vcpu.gpr[7] = 
		threads_ctx[tid].vcpu.gpr[8];
	
	/* update */
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) =
		(*((uint16_t *)(bitmap + VIRT2BYTE(dst))) & ~(WORD_MASK <<
							      VIRT2BIT(dst))) |
		((uint16_t)(threads_ctx[tid].vcpu.gpr[src] & VCPU_MASK16) <<
		VIRT2BIT(dst));
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 16-bit 
 * register and a memory location as
 * t[dst] = t[src] (src is a register)
 *
 * @tid:	the thread id
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opw(THREADID tid, ADDRINT dst, uint32_t src)
{
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) =
		(*((uint16_t *)(bitmap + VIRT2BYTE(dst))) & ~(WORD_MASK <<
							      VIRT2BIT(dst))) |
		((uint16_t)(threads_ctx[tid].vcpu.gpr[src] & VCPU_MASK16) <<
		VIRT2BIT(dst));
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 32-bit
 * register and a memory location
 * as t[EAX] = t[src]; return the result
 * of EAX == src and also store the
 * original tag value of EAX in
 * the scratch register
 *
 * @tid:	the thread id
 * @dst_val:	destination register value
 * @src:	source memory address
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
r2m_xfer_opl_fast(THREADID tid, uint32_t dst_val, ADDRINT src)
{
	/* save the tag value of dst in the scratch register */
	threads_ctx[tid].vcpu.gpr[8] = 
		threads_ctx[tid].vcpu.gpr[7];
	
	/* update */
	threads_ctx[tid].vcpu.gpr[7] =
		(*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK32;
	
	/* compare the dst and src values; the original values the tag bits */
	return (dst_val == *(uint32_t *)src);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 32-bit 
 * register and a n-memory locations as
 * t[dst] = t[src]; src is EAX
 *
 * @tid:	the thread id
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 * @count:	memory double words
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opln(THREADID tid, ADDRINT dst, uint32_t count)
{
	/* the source register is taged */
	if (threads_ctx[tid].vcpu.gpr[7])
		tagmap_setn(dst, (count << 2));
	/* the source register is clear */
	else
		tagmap_clrn(dst, (count << 2));
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 32-bit 
 * register and a memory location
 * as t[dst] = t[src]; restore the value
 * of EAX from the scratch register
 *
 * @tid:	the thread id
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opl_slow(THREADID tid, ADDRINT dst, uint32_t src)
{
	/* restore the tag value from the scratch register */
	threads_ctx[tid].vcpu.gpr[7] = 
		threads_ctx[tid].vcpu.gpr[8];
	
	/* update */
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) =
		(*((uint16_t *)(bitmap + VIRT2BYTE(dst))) & ~(LONG_MASK <<
							      VIRT2BIT(dst))) |
		((uint16_t)(threads_ctx[tid].vcpu.gpr[src] & VCPU_MASK32) <<
		VIRT2BIT(dst));
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between a 32-bit 
 * register and a memory location as
 * t[dst] = t[src] (src is a register)
 *
 * @tid:	the thread id
 * @dst:	destination memory address
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opl(THREADID tid, ADDRINT dst, uint32_t src)
{
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) =
		(*((uint16_t *)(bitmap + VIRT2BYTE(dst))) & ~(LONG_MASK <<
							      VIRT2BIT(dst))) |
		((uint16_t)(threads_ctx[tid].vcpu.gpr[src] & VCPU_MASK32) <<
		VIRT2BIT(dst));
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 16-bit 
 * memory locations as t[dst] = t[src]
 *
 * @dst:	destination memory address
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2m_xfer_opw(ADDRINT dst, ADDRINT src)
{
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) =
		(*((uint16_t *)(bitmap + VIRT2BYTE(dst))) & ~(WORD_MASK <<
							      VIRT2BIT(dst))) |
		(((*((uint16_t *)(bitmap + VIRT2BYTE(src)))) >> VIRT2BIT(src))
		& WORD_MASK) << VIRT2BIT(dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 8-bit 
 * memory locations as t[dst] = t[src]
 *
 * @dst:	destination memory address
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2m_xfer_opb(ADDRINT dst, ADDRINT src)
{
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) =
		(*((uint16_t *)(bitmap + VIRT2BYTE(dst))) & ~(BYTE_MASK <<
							      VIRT2BIT(dst))) |
		(((*((uint16_t *)(bitmap + VIRT2BYTE(src)))) >> VIRT2BIT(src))
		& BYTE_MASK) << VIRT2BIT(dst);
}

/*
 * tag propagation (analysis function)
 *
 * propagate tag between two 32-bit 
 * memory locations as t[dst] = t[src]
 *
 * @dst:	destination memory address
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
m2m_xfer_opl(ADDRINT dst, ADDRINT src)
{
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) =
		(*((uint16_t *)(bitmap + VIRT2BYTE(dst))) & ~(LONG_MASK <<
							      VIRT2BIT(dst))) |
		(((*((uint16_t *)(bitmap + VIRT2BYTE(src)))) >> VIRT2BIT(src))
		& LONG_MASK) << VIRT2BIT(dst);
}

/*
 * tag propagation (analysis function)
 *
 * instrumentation helper; returns the flag that
 * takes as argument -- seems lame, but it is
 * necessary for aiding conditional analysis to
 * be inlined. Typically used with INS_InsertIfCall()
 * in order to return true (i.e., allow the execution
 * of the function that has been instrumented with
 * INS_InsertThenCall()) only once
 *
 * first_iteration:	flag; indicates whether the rep-prefixed instruction is
 * 			executed for the first time or not
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
rep_predicate(BOOL first_iteration)
{
	/* return the flag; typically this is true only once */
	return first_iteration; 
}

/*
 * tag propagation (analysis function)
 *
 * restore the tag values for all the
 * 16-bit general purpose registers from
 * the memory
 *
 * NOTE: special case for POPA instruction 
 *
 * @tid:	the thread id
 * @src:	the source memory address	
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_restore_opw(THREADID tid, ADDRINT src)
{
	/* restore DI */
	threads_ctx[tid].vcpu.gpr[0] =
		(threads_ctx[tid].vcpu.gpr[0] & ~VCPU_MASK16) |
		((*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK16);
	
	/* update the source memory */
	src += 2;
	
	/* restore SI */
	threads_ctx[tid].vcpu.gpr[1] =
		(threads_ctx[tid].vcpu.gpr[1] & ~VCPU_MASK16) |
		((*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK16);
	
	/* update the source memory */
	src += 2;
	
	/* restore BP */
	threads_ctx[tid].vcpu.gpr[2] =
		(threads_ctx[tid].vcpu.gpr[2] & ~VCPU_MASK16) |
		((*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK16);
	
	/* update the source memory; skip 4 bytes (i.e., sp) */
	src += 4;
	
	/* restore BX */
	threads_ctx[tid].vcpu.gpr[4] =
		(threads_ctx[tid].vcpu.gpr[4] & ~VCPU_MASK16) |
		((*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK16);
	
	/* update the source memory */
	src += 2;

	/* restore DX */
	threads_ctx[tid].vcpu.gpr[5] =
		(threads_ctx[tid].vcpu.gpr[5] & ~VCPU_MASK16) |
		((*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK16);
	
	/* update the source memory */
	src += 2;
	
	/* restore CX */
	threads_ctx[tid].vcpu.gpr[6] =
		(threads_ctx[tid].vcpu.gpr[6] & ~VCPU_MASK16) |
		((*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK16);
	
	/* update the source memory */
	src += 2;
	
	/* restore AX */
	threads_ctx[tid].vcpu.gpr[7] =
		(threads_ctx[tid].vcpu.gpr[7] & ~VCPU_MASK16) |
		((*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK16);
}

/*
 * tag propagation (analysis function)
 *
 * restore the tag values for all the
 * 32-bit general purpose registers from
 * the memory
 *
 * NOTE: special case for POPAD instruction 
 *
 * @tid:	the thread id
 * @src:	the source memory address	
 */
static void PIN_FAST_ANALYSIS_CALL
m2r_restore_opl(THREADID tid, ADDRINT src)
{
	/* restore EDI */
	threads_ctx[tid].vcpu.gpr[0] =
		(*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK32;

	/* update the source memory */
	src += 4;
	
	/* restore ESI */
	threads_ctx[tid].vcpu.gpr[1] =
		(*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK32;
	
	/* update the source memory */
	src += 4;
	
	/* restore EBP */
	threads_ctx[tid].vcpu.gpr[2] =
		(*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK32;
	
	/* update the source memory; skip 4 bytes (i.e., ESP) */
	src += 8;
	
	/* restore EBX */
	threads_ctx[tid].vcpu.gpr[4] =
		(*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK32;
	
	/* update the source memory */
	src += 4;

	/* restore EDX */
	threads_ctx[tid].vcpu.gpr[5] =
		(*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK32;
	
	/* update the source memory */
	src += 4;
	
	/* restore ECX */
	threads_ctx[tid].vcpu.gpr[6] =
		(*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK32;
	
	/* update the source memory */
	src += 4;
	
	/* restore EAX */
	threads_ctx[tid].vcpu.gpr[7] =
		(*((uint16_t *)(bitmap + VIRT2BYTE(src))) >> VIRT2BIT(src)) &
		VCPU_MASK32;
}

/*
 * tag propagation (analysis function)
 *
 * save the tag values for all the 16-bit
 * general purpose registers into the memory
 *
 * NOTE: special case for PUSHA instruction
 *
 * @tid:	the thread id
 * @dst:	the destination memory address
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_save_opw(THREADID tid, ADDRINT dst)
{
	/* save DI */
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) =
		(*((uint16_t *)(bitmap + VIRT2BYTE(dst))) & ~(WORD_MASK <<
							      VIRT2BIT(dst))) |
		((uint16_t)(threads_ctx[tid].vcpu.gpr[0] & VCPU_MASK16) <<
		VIRT2BIT(dst));

	/* update the destination memory */
	dst += 2;

	/* save SI */
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) =
		(*((uint16_t *)(bitmap + VIRT2BYTE(dst))) & ~(WORD_MASK <<
							      VIRT2BIT(dst))) |
		((uint16_t)(threads_ctx[tid].vcpu.gpr[1] & VCPU_MASK16) <<
		VIRT2BIT(dst));

	/* update the destination memory */
	dst += 2;

	/* save BP */
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) =
		(*((uint16_t *)(bitmap + VIRT2BYTE(dst))) & ~(WORD_MASK <<
							      VIRT2BIT(dst))) |
		((uint16_t)(threads_ctx[tid].vcpu.gpr[2] & VCPU_MASK16) <<
		VIRT2BIT(dst));

	/* update the destination memory */
	dst += 2;

	/* save SP */
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) =
		(*((uint16_t *)(bitmap + VIRT2BYTE(dst))) & ~(WORD_MASK <<
							      VIRT2BIT(dst))) |
		((uint16_t)(threads_ctx[tid].vcpu.gpr[3] & VCPU_MASK16) <<
		VIRT2BIT(dst));

	/* update the destination memory */
	dst += 2;

	/* save BX */
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) =
		(*((uint16_t *)(bitmap + VIRT2BYTE(dst))) & ~(WORD_MASK <<
							      VIRT2BIT(dst))) |
		((uint16_t)(threads_ctx[tid].vcpu.gpr[4] & VCPU_MASK16) <<
		VIRT2BIT(dst));

	/* update the destination memory */
	dst += 2;

	/* save DX */
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) =
		(*((uint16_t *)(bitmap + VIRT2BYTE(dst))) & ~(WORD_MASK <<
							      VIRT2BIT(dst))) |
		((uint16_t)(threads_ctx[tid].vcpu.gpr[5] & VCPU_MASK16) <<
		VIRT2BIT(dst));

	/* update the destination memory */
	dst += 2;

	/* save CX */
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) =
		(*((uint16_t *)(bitmap + VIRT2BYTE(dst))) & ~(WORD_MASK <<
							      VIRT2BIT(dst))) |
		((uint16_t)(threads_ctx[tid].vcpu.gpr[6] & VCPU_MASK16) <<
		VIRT2BIT(dst));

	/* update the destination memory */
	dst += 2;

	/* save AX */
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) =
		(*((uint16_t *)(bitmap + VIRT2BYTE(dst))) & ~(WORD_MASK <<
							      VIRT2BIT(dst))) |
		((uint16_t)(threads_ctx[tid].vcpu.gpr[7] & VCPU_MASK16) <<
		VIRT2BIT(dst));
}

/*
 * tag propagation (analysis function)
 *
 * save the tag values for all the 32-bit
 * general purpose registers into the memory
 *
 * NOTE: special case for PUSHAD instruction 
 *
 * @tid:	the thread id
 * @dst:	the destination memory address
 */
static void PIN_FAST_ANALYSIS_CALL
r2m_save_opl(THREADID tid, ADDRINT dst)
{
	/* save EDI */
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) =
		(*((uint16_t *)(bitmap + VIRT2BYTE(dst))) & ~(LONG_MASK <<
							      VIRT2BIT(dst))) |
		((uint16_t)(threads_ctx[tid].vcpu.gpr[0] & VCPU_MASK32) <<
		VIRT2BIT(dst));

	/* update the destination memory address */
	dst += 4;

	/* save ESI */
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) =
		(*((uint16_t *)(bitmap + VIRT2BYTE(dst))) & ~(LONG_MASK <<
							      VIRT2BIT(dst))) |
		((uint16_t)(threads_ctx[tid].vcpu.gpr[1] & VCPU_MASK32) <<
		VIRT2BIT(dst));
	
	/* update the destination memory address */
	dst += 4;

	/* save EBP */
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) =
		(*((uint16_t *)(bitmap + VIRT2BYTE(dst))) & ~(LONG_MASK <<
							      VIRT2BIT(dst))) |
		((uint16_t)(threads_ctx[tid].vcpu.gpr[2] & VCPU_MASK32) <<
		VIRT2BIT(dst));
	
	/* update the destination memory address */
	dst += 4;

	/* save ESP */
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) =
		(*((uint16_t *)(bitmap + VIRT2BYTE(dst))) & ~(LONG_MASK <<
							      VIRT2BIT(dst))) |
		((uint16_t)(threads_ctx[tid].vcpu.gpr[3] & VCPU_MASK32) <<
		VIRT2BIT(dst));

	/* update the destination memory address */
	dst += 4;

	/* save EBX */
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) =
		(*((uint16_t *)(bitmap + VIRT2BYTE(dst))) & ~(LONG_MASK <<
							      VIRT2BIT(dst))) |
		((uint16_t)(threads_ctx[tid].vcpu.gpr[4] & VCPU_MASK32) <<
		VIRT2BIT(dst));
	
	/* update the destination memory address */
	dst += 4;

	/* save EDX */
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) =
		(*((uint16_t *)(bitmap + VIRT2BYTE(dst))) & ~(LONG_MASK <<
							      VIRT2BIT(dst))) |
		((uint16_t)(threads_ctx[tid].vcpu.gpr[5] & VCPU_MASK32) <<
		VIRT2BIT(dst));
	
	/* update the destination memory address */
	dst += 4;

	/* save ECX */
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) =
		(*((uint16_t *)(bitmap + VIRT2BYTE(dst))) & ~(LONG_MASK <<
							      VIRT2BIT(dst))) |
		((uint16_t)(threads_ctx[tid].vcpu.gpr[6] & VCPU_MASK32) <<
		VIRT2BIT(dst));
	
	/* update the destination memory address */
	dst += 4;
	
	/* save EAX */
	*((uint16_t *)(bitmap + VIRT2BYTE(dst))) =
		(*((uint16_t *)(bitmap + VIRT2BYTE(dst))) & ~(LONG_MASK <<
							      VIRT2BIT(dst))) |
		((uint16_t)(threads_ctx[tid].vcpu.gpr[7] & VCPU_MASK32) <<
		VIRT2BIT(dst));
}

/*
 * instruction inspection (instrumentation function)
 *
 * analyze every instruction and instrument it
 * for propagating the tag bits accordingly
 *
 * @ins:	the instruction to be instrumented
 */
void
ins_inspect(INS ins)
{
	/* 
	 * temporaries;
	 * source, destination, base, and index registers
	 */
	REG reg_dst, reg_src, reg_base, reg_indx;

	/* use XED to decode the instruction and extract its opcode */
	xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);

	/* sanity check */
	if (unlikely(ins_indx <= XED_ICLASS_INVALID || 
				ins_indx >= XED_ICLASS_LAST)) {
		warnx("%s:%u: unknown opcode(opcode=%d)",
			__func__, __LINE__, ins_indx);

		/* done */
		return;
	}

	/* analyze the instruction */
	switch (ins_indx) {
		/* adc */
		case XED_ICLASS_ADC:
		/* add */
		case XED_ICLASS_ADD:
		/* and */
		case XED_ICLASS_AND:
		/* or */
		case XED_ICLASS_OR:
		/* xor */
		case XED_ICLASS_XOR:
		/* sbb */
		case XED_ICLASS_SBB:
		/* sub */
		case XED_ICLASS_SUB:
			/*
			 * the general format of these instructions
			 * is the following: dst {op}= src, where
			 * op can be +, -, &, |, etc. We tag the
			 * destination if the source is also taged
			 * (i.e., t[dst] |= t[src])
			 */
			/* 2nd operand is immediate; do nothing */
			if (INS_OperandIsImmediate(ins, OP_1))
				break;

			/* both operands are registers */
			if (INS_MemoryOperandCount(ins) == 0) {
				/* extract the operands */
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst)) {
					/* check for x86 clear register idiom */
					switch (ins_indx) {
						/* xor, sub, sbb */
						case XED_ICLASS_XOR:
						case XED_ICLASS_SUB:
						case XED_ICLASS_SBB:
							/* same dst, src */
							if (reg_dst == reg_src) 
							{
								/* clear */
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								AFUNPTR(r_clrl),
							IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_UINT32,
							REG32_INDX(reg_dst),
								IARG_END);

								/* done */
								break;
							}
						/* default behavior */
						default:
							/* 
							 * propagate the tag
							 * markings accordingly
							 */
							INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(r2r_binary_opl),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32,
							REG32_INDX(reg_dst),
							IARG_UINT32,
							REG32_INDX(reg_src),
							IARG_END);
					}
				}
				/* 16-bit operands */
				else if (REG_is_gr16(reg_dst)) {
					/* check for x86 clear register idiom */
					switch (ins_indx) {
						/* xor, sub, sbb */
						case XED_ICLASS_XOR:
						case XED_ICLASS_SUB:
						case XED_ICLASS_SBB:
							/* same dst, src */
							if (reg_dst == reg_src) 
							{
								/* clear */
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								AFUNPTR(r_clrw),
							IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_UINT32,
							REG16_INDX(reg_dst),
								IARG_END);

								/* done */
								break;
							}
						/* default behavior */
						default:
						/* propagate tags accordingly */
							INS_InsertCall(ins,
								IPOINT_BEFORE,
							AFUNPTR(r2r_binary_opw),
							IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_UINT32,
							REG16_INDX(reg_dst),
								IARG_UINT32,
							REG16_INDX(reg_src),
								IARG_END);
					}
				}
				/* 8-bit operands */
				else {
					/* check for x86 clear register idiom */
					switch (ins_indx) {
						/* xor, sub, sbb */
						case XED_ICLASS_XOR:
						case XED_ICLASS_SUB:
						case XED_ICLASS_SBB:
							/* same dst, src */
							if (reg_dst == reg_src) 
							{
								/* clear */
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								AFUNPTR(r_clrb),
							IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_UINT32,
							REG8_INDX(reg_dst),
								IARG_END);

								/* done */
								break;
							}
						/* default behavior */
						default:
						/* propagate tags accordingly */
					if (REG_is_Lower8(reg_dst) &&
							REG_is_Lower8(reg_src))
						/* lower 8-bit registers */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_UINT32, 0,
						IARG_END);
					else if(REG_is_Upper8(reg_dst) &&
							REG_is_Upper8(reg_src))
						/* upper 8-bit registers */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_UINT32, 1,
						IARG_END);
					else if (REG_is_Lower8(reg_dst))
						/* 
						 * destination register is a
						 * lower 8-bit register and
						 * source register is an upper
						 * 8-bit register
						 */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opb_lu),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_END);
					else
						/* 
						 * destination register is an
						 * upper 8-bit register and
						 * source register is a lower
						 * 8-bit register
						 */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opb_ul),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_END);
					}
				}
			}
			/* 
			 * 2nd operand is memory;
			 * we optimize for that case, since most
			 * instructions will have a register as
			 * the first operand -- leave the result
			 * into the reg and use it later
			 */
			else if (INS_OperandIsMemory(ins, OP_1)) {
				/* extract the register operand */
				reg_dst = INS_OperandReg(ins, OP_0);

				/* 32-bit operands */
				if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_binary_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				/* 16-bit operands */
				else if (REG_is_gr16(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_binary_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				/* 8-bit operands */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_binary_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
					IARG_UINT32, REG_is_Upper8(reg_dst),
						IARG_END);
			}
			/* 1st operand is memory */
			else {
				/* extract the register operand */
				reg_src = INS_OperandReg(ins, OP_1);

				/* 32-bit operands */
				if (REG_is_gr32(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_binary_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_END);
				/* 16-bit operands */
				else if (REG_is_gr16(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_binary_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_END);
				/* 8-bit operands */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_binary_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG8_INDX(reg_src),
					IARG_UINT32, REG_is_Upper8(reg_src),
						IARG_END);
			}

			/* done */
			break;
		/* bsf */
		case XED_ICLASS_BSF:
		/* bsr */
		case XED_ICLASS_BSR:
		/* mov */
		case XED_ICLASS_MOV:
			/*
			 * the general format of these instructions
			 * is the following: dst = src. We move the
			 * tag of the source to the destination
			 * (i.e., t[dst] = t[src])
			 */
			/* 2nd operand is immediate; clear the destination */
			if (INS_OperandIsImmediate(ins, OP_1)) {
				/* destination operand is a memory address */
				if (INS_OperandIsMemory(ins, OP_0)) {
					/* clear n-bytes */
					switch (INS_OperandWidth(ins, OP_1)) {
						/* 4 bytes */
						case MEM_LONG_LEN:
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(tagmap_clrl),
							IARG_FAST_ANALYSIS_CALL,
							IARG_MEMORYWRITE_EA,
							IARG_END);

							/* done */
							break;
						/* 2 bytes */
						case MEM_WORD_LEN:
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(tagmap_clrw),
							IARG_FAST_ANALYSIS_CALL,
							IARG_MEMORYWRITE_EA,
							IARG_END);

							/* done */
							break;
						/* 1 byte */
						case MEM_BYTE_LEN:
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(tagmap_clrb),
							IARG_FAST_ANALYSIS_CALL,
							IARG_MEMORYWRITE_EA,
							IARG_END);

							/* done */
							break;
						/* make the compiler happy */
						default:
							/* done */
							return;
					}
				}
				/* destination operand is a register */
				else {
					/* extract the operand */
					reg_dst = INS_OperandReg(ins, OP_0);

					/* 32-bit operand */
					if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(r_clrl),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
							IARG_END);
					/* 16-bit operand */
					else if (REG_is_gr16(reg_dst))
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(r_clrw),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
							IARG_END);
					/* 8-bit operand */
					else
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(r_clrb),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
					IARG_UINT32, REG_is_Upper8(reg_dst),
							IARG_END);
				}
			}
			/* both operands are registers */
			else if (INS_MemoryOperandCount(ins) == 0) {
				/* extract the operands */
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_END);
				/* 16-bit operands */
				else if (REG_is_gr16(reg_dst) && 
						!REG_is_seg(reg_src))
					/* propagate tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_END);
				/* 16-bit operands & segment register */
				else if (REG_is_gr16(reg_dst) && 
						REG_is_seg(reg_src))
					/* propagate tag accordingly; clear */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r_clrw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_END);
				/* 8-bit operands */
				else if (REG_is_gr8(reg_dst)) {
					/* propagate tag accordingly */
					if (REG_is_Lower8(reg_dst) &&
							REG_is_Lower8(reg_src))
						/* lower 8-bit registers */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_UINT32, 0,
						IARG_END);
					else if(REG_is_Upper8(reg_dst) &&
							REG_is_Upper8(reg_src))
						/* upper 8-bit registers */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_UINT32, 1,
						IARG_END);
					else if (REG_is_Lower8(reg_dst))
						/* 
						 * destination register is a
						 * lower 8-bit register and
						 * source register is an upper
						 * 8-bit register
						 */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb_lu),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_END);
					else
						/* 
						 * destination register is an
						 * upper 8-bit register and
						 * source register is a lower
						 * 8-bit register
						 */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb_ul),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_END);
				}
			}
			/* 
			 * 2nd operand is memory;
			 * we optimize for that case, since most
			 * instructions will have a register as
			 * the first operand -- leave the result
			 * into the reg and use it later
			 */
			else if (INS_OperandIsMemory(ins, OP_1)) {
				/* extract the register operand */
				reg_dst = INS_OperandReg(ins, OP_0);

				/* 32-bit operands */
				if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				/* 16-bit operands */
				else if (REG_is_gr16(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				/* 8-bit operands */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG8_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
					IARG_UINT32, REG_is_Upper8(reg_dst),
						IARG_END);
			}
			/* 1st operand is memory */
			else {
				/* extract the register operand */
				reg_src = INS_OperandReg(ins, OP_1);

				/* 32-bit operands */
				if (REG_is_gr32(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_END);
				/* 16-bit operands */
				else if (REG_is_gr16(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_END);
				/* 16-bit operands & segment register */
				else if (REG_is_seg(reg_src))
					/* 
					 * propagate the tag accordingly;
					 * clear
					 */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(tagmap_clrw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);
				/* 8-bit operands */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG8_INDX(reg_src),
					IARG_UINT32, REG_is_Upper8(reg_src),
						IARG_END);
			}

			/* done */
			break;
		/* conditional movs */
		case XED_ICLASS_CMOVB:
		case XED_ICLASS_CMOVBE:
		case XED_ICLASS_CMOVL:
		case XED_ICLASS_CMOVLE:
		case XED_ICLASS_CMOVNB:
		case XED_ICLASS_CMOVNBE:
		case XED_ICLASS_CMOVNL:
		case XED_ICLASS_CMOVNLE:
		case XED_ICLASS_CMOVNO:
		case XED_ICLASS_CMOVNP:
		case XED_ICLASS_CMOVNS:
		case XED_ICLASS_CMOVNZ:
		case XED_ICLASS_CMOVO:
		case XED_ICLASS_CMOVP:
		case XED_ICLASS_CMOVS:
		case XED_ICLASS_CMOVZ:
			/*
			 * the general format of these instructions
			 * is the following: dst = src iff cond. We
			 * move the tag of the source to the destination
			 * iff the corresponding condition is met
			 * (i.e., t[dst] = t[src])
			 */
			/* 2nd operand is immediate; clear the destination */
			/* both operands are registers */
			if (INS_MemoryOperandCount(ins) == 0) {
				/* extract the operands */
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_END);
				/* 16-bit operands */
				else 
					/* propagate tag accordingly */
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_END);
			}
			/* 
			 * 2nd operand is memory;
			 * we optimize for that case, since most
			 * instructions will have a register as
			 * the first operand -- leave the result
			 * into the reg and use it later
			 */
			else {
				/* extract the register operand */
				reg_dst = INS_OperandReg(ins, OP_0);

				/* 32-bit operands */
				if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				/* 16-bit operands */
				else
					/* propagate the tag accordingly */
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
			}

			/* done */
			break;
		/* 
		 * cbw;
		 * move the tag associated with AL to AH
		 */
		case XED_ICLASS_CBW:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(r2r_xfer_opb_ul),
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG8_INDX(REG_AH),
				IARG_UINT32, REG8_INDX(REG_AL),
				IARG_END);

			/* done */
			break;
		/*
		 * cwd;
		 * move the tag associated with AX to DX
		 */
		case XED_ICLASS_CWD:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(r2r_xfer_opw),
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG16_INDX(REG_DX),
				IARG_UINT32, REG16_INDX(REG_AX),
				IARG_END);

			/* done */
			break;
		/* 
		 * cwde;
		 * move the tag associated with AX to EAX
		 */
		case XED_ICLASS_CWDE:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(r2r_ext_oplw),
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_END);

			/* done */
			break;
		/*
		 * cdq;
		 * move the tag associated with EAX to EDX
		 */
		case XED_ICLASS_CDQ:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(r2r_xfer_opl),
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG32_INDX(REG_EDX),
				IARG_UINT32, REG32_INDX(REG_EAX),
				IARG_END);

			/* done */
			break;
		/* movsx */
		case XED_ICLASS_MOVSX:
		/* movxz */
		case XED_ICLASS_MOVZX:
			/*
			 * the general format of these instructions
			 * is the following: dst = src. We move the
			 * tag of the source to the destination
			 * (i.e., t[dst] = t[src]) and we extend the
			 * tag bits accordingly
			 */
			/* 2nd operand is immediate; clear the destination */
			/* both operands are registers */
			if (INS_MemoryOperandCount(ins) == 0) {
				/* extract the operands */
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				
				/* 16-bit & 8-bit operands */
				if (REG_is_gr16(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opwb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
					IARG_UINT32, REG_is_Upper8(reg_src),
						IARG_END);
				/* 32-bit & 16-bit operands */
				else if (REG_is_gr16(reg_src))
					/* propagate the tag accordingly */
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_oplw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_END);
				/* 32-bit & 8-bit operands */
				else
					/* propagate the tag accordingly */
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_oplb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
					IARG_UINT32, REG_is_Upper8(reg_src),
						IARG_END);
			}
			/* 2nd operand is memory */
			else {
				/* extract the operands */
				reg_dst = INS_OperandReg(ins, OP_0);
				
				/* 16-bit & 8-bit operands */
				if (REG_is_gr16(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_xfer_opwb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				/* 32-bit & 16-bit operands */
				else if (INS_MemoryWriteSize(ins) ==
						BIT2BYTE(MEM_WORD_LEN))
					/* propagate the tag accordingly */
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_xfer_oplw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				/* 32-bit & 8-bit operands */
				else
					/* propagate the tag accordingly */
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_xfer_oplb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
			}

			/* done */
			break;
		/* div */
		case XED_ICLASS_DIV:
		/* idiv */
		case XED_ICLASS_IDIV:
			/*
			 * the general format of these brain-dead and
			 * totally corrupted instructions is the following:
			 * dst1:dst2 /= src. We tag the destination operands
			 * if the source is also taged
			 * (i.e., t[dst1]:t[dst2] |= t[src])
			 */
			/* memory operand */
			if (INS_OperandIsMemory(ins, OP_0))
				/* differentiate based on the memory size */
				switch (INS_MemoryWriteSize(ins)) {
					/* 4 bytes */
					case BIT2BYTE(MEM_LONG_LEN):
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
						AFUNPTR(m2r_ternary_opl),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_MEMORYREAD_EA,
							IARG_END);

						/* done */
						break;
					/* 2 bytes */
					case BIT2BYTE(MEM_WORD_LEN):
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
						AFUNPTR(m2r_ternary_opw),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_MEMORYREAD_EA,
							IARG_END);

						/* done */
						break;
					/* 1 byte */
					case BIT2BYTE(MEM_BYTE_LEN):
					default:
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
						AFUNPTR(m2r_ternary_opwb),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_MEMORYREAD_EA,
							IARG_END);

						/* done */
						break;
				}
			/* register operand */
			else {
				/* extract the operand */
				reg_src = INS_OperandReg(ins, OP_0);
				
				/* 32-bit operand */
				if (REG_is_gr32(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_ternary_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_END);
				/* 16-bit operand */
				else if (REG_is_gr16(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_ternary_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_END);
				/* 8-bit operand */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_ternary_opwb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_src),
					IARG_UINT32, REG_is_Upper8(reg_src),
						IARG_END);
			}

			/* done */
			break;
		/* mul;
		 * the general format of this brain-dead and
		 * totally corrupted instruction is the following:
		 * dst1 = dst2 * src and dst2 = dst1 * src. We tag the
		 * destination operands if the source is also taged
		 * (i.e., t[dst1] = t[dst2] | t[src] and
		 * t[dst2] = t[dst1] | t[src])
		 */
		case XED_ICLASS_MUL:
			/* memory operand */
			if (INS_OperandIsMemory(ins, OP_0))
				/* differentiate based on the memory size */
				switch (INS_MemoryWriteSize(ins)) {
					/* 4 bytes */
					case BIT2BYTE(MEM_LONG_LEN):
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
						AFUNPTR(m2r_ternary_opl2),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_MEMORYREAD_EA,
							IARG_END);

						/* done */
						break;
					/* 2 bytes */
					case BIT2BYTE(MEM_WORD_LEN):
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
						AFUNPTR(m2r_ternary_opw2),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_MEMORYREAD_EA,
							IARG_END);

						/* done */
						break;
					/* 1 byte */
					case BIT2BYTE(MEM_BYTE_LEN):
					default:
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
						AFUNPTR(m2r_ternary_opwb2),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_MEMORYREAD_EA,
							IARG_END);

						/* done */
						break;
				}
			/* register operand */
			else {
				/* extract the operand */
				reg_src = INS_OperandReg(ins, OP_0);
				
				/* 32-bit operand */
				if (REG_is_gr32(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_ternary_opl2),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_END);
				/* 16-bit operand */
				else if (REG_is_gr16(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_ternary_opw2),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_END);
				/* 8-bit operand */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_ternary_opwb2),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_src),
					IARG_UINT32, REG_is_Upper8(reg_src),
						IARG_END);
			}

			/* done */
			break;
		/*
		 * imul;
		 * I'm still wondering how brain-damaged the
		 * ISA architect should be in order to come
		 * up with something so ugly as the IMUL 
		 * instruction
		 */
		case XED_ICLASS_IMUL:
			/* one-operand form */
			if (INS_OperandIsImplicit(ins, OP_1)) {
				/* memory operand */
				if (INS_OperandIsMemory(ins, OP_0))
				/* differentiate based on the memory size */
				switch (INS_MemoryWriteSize(ins)) {
					/* 4 bytes */
					case BIT2BYTE(MEM_LONG_LEN):
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
						AFUNPTR(m2r_ternary_opl2),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_MEMORYREAD_EA,
							IARG_END);

						/* done */
						break;
					/* 2 bytes */
					case BIT2BYTE(MEM_WORD_LEN):
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
						AFUNPTR(m2r_ternary_opw2),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_MEMORYREAD_EA,
							IARG_END);

						/* done */
						break;
					/* 1 byte */
					case BIT2BYTE(MEM_BYTE_LEN):
					default:
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
						AFUNPTR(m2r_ternary_opwb2),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_MEMORYREAD_EA,
							IARG_END);

						/* done */
						break;
				}
			/* register operand */
			else {
				/* extract the operand */
				reg_src = INS_OperandReg(ins, OP_0);
				
				/* 32-bit operand */
				if (REG_is_gr32(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_ternary_opl2),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_END);
				/* 16-bit operand */
				else if (REG_is_gr16(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_ternary_opw2),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_END);
				/* 8-bit operand */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_ternary_opwb2),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_src),
					IARG_UINT32, REG_is_Upper8(reg_src),
						IARG_END);
				}
			}
			/* two/three-operands form */
			else {
				/* 2nd operand is immediate; do nothing */
				if (INS_OperandIsImmediate(ins, OP_1))
					break;

				/* both operands are registers */
				if (INS_MemoryOperandCount(ins) == 0) {
					/* extract the operands */
					reg_dst = INS_OperandReg(ins, OP_0);
					reg_src = INS_OperandReg(ins, OP_1);
				
					/* 32-bit operands */
					if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(r2r_binary_opl),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_src),
							IARG_END);
					/* 16-bit operands */
					else
					/* propagate tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(r2r_binary_opw),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
							IARG_END);
				}
				/* 
				 * 2nd operand is memory;
				 * we optimize for that case, since most
				 * instructions will have a register as
				 * the first operand -- leave the result
				 * into the reg and use it later
				 */
				else {
					/* extract the register operand */
					reg_dst = INS_OperandReg(ins, OP_0);

					/* 32-bit operands */
					if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(m2r_binary_opl),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
							IARG_MEMORYREAD_EA,
							IARG_END);
					/* 16-bit operands */
					else
					/* propagate the tag accordingly */
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(m2r_binary_opw),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
							IARG_MEMORYREAD_EA,
							IARG_END);
				}
			}

			/* done */
			break;
		/* conditional sets */
		case XED_ICLASS_SETB:
		case XED_ICLASS_SETBE:
		case XED_ICLASS_SETL:
		case XED_ICLASS_SETLE:
		case XED_ICLASS_SETNB:
		case XED_ICLASS_SETNBE:
		case XED_ICLASS_SETNL:
		case XED_ICLASS_SETNLE:
		case XED_ICLASS_SETNO:
		case XED_ICLASS_SETNP:
		case XED_ICLASS_SETNS:
		case XED_ICLASS_SETNZ:
		case XED_ICLASS_SETO:
		case XED_ICLASS_SETP:
		case XED_ICLASS_SETS:
		case XED_ICLASS_SETZ:
			/*
			 * clear the tag information associated with the
			 * destination operand
			 */
			/* register operand */
			if (INS_MemoryOperandCount(ins) == 0) {
				/* extract the operand */
				reg_dst = INS_OperandReg(ins, OP_0);
				
				/* propagate tag accordingly */
				INS_InsertPredicatedCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(r_clrb),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG8_INDX(reg_dst),
					IARG_UINT32, REG_is_Upper8(reg_dst),
					IARG_END);
			}
			/* memory operand */
			else
				/* propagate the tag accordingly */
				INS_InsertPredicatedCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(tagmap_clrb),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_END);

			/* done */
			break;
		/* 
		 * stmxcsr;
		 * clear the destination operand (register only)
		 */
		case XED_ICLASS_STMXCSR:
			/* propagate tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(tagmap_clrl),
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_END);
		
			/* done */
			break;
		/* smsw */
		case XED_ICLASS_SMSW:
		/* str */
		case XED_ICLASS_STR:
			/*
			 * clear the tag information associated with
			 * the destination operand
			 */
			/* register operand */
			if (INS_MemoryOperandCount(ins) == 0) {
				/* extract the operand */
				reg_dst = INS_OperandReg(ins, OP_0);
				
				/* 16-bit register */
				if (REG_is_gr16(reg_dst))
					/* propagate tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r_clrw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_END);
				/* 32-bit register */
				else 
					/* propagate tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r_clrl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_END);
			}
			/* memory operand */
			else
				/* propagate tag accordingly */
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(tagmap_clrw),
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_END);

			/* done */
			break;
		/* 
		 * lar;
		 * clear the destination operand (register only)
		 */
		case XED_ICLASS_LAR:
			/* extract the 1st operand */
			reg_dst = INS_OperandReg(ins, OP_0);

			/* 16-bit register */
			if (REG_is_gr16(reg_dst))
				/* propagate tag accordingly */
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(r_clrw),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_END);
			/* 32-bit register */
			else
				/* propagate tag accordingly */
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(r_clrl),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_END);

			/* done */
			break;
		/* rdmsr */
		case XED_ICLASS_RDMSR:
		/* rdpmc */
		case XED_ICLASS_RDPMC:
		/* rdtsc */
		case XED_ICLASS_RDTSC:
			/*
			 * clear the tag information associated with
			 * EAX and EDX
			 */
			/* propagate tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(r_clrl2),
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_END);

			/* done */
			break;
		/* 
		 * cpuid;
		 * clear the tag information associated with
		 * EAX, EBX, ECX, and EDX 
		 */
		case XED_ICLASS_CPUID:
			/* propagate tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(r_clrl4),
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_END);

			/* done */
			break;
		/* 
		 * lahf;
		 * clear the tag information of AH
		 */
		case XED_ICLASS_LAHF:
			/* propagate tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(r_clrb),
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG8_INDX(REG_AH),
				IARG_UINT32, 1,
				IARG_END);

			/* done */
			break;
		/* 
		 * cmpxchg;
		 * t[dst] = t[src] iff EAX/AX/AL == dst, else
		 * t[EAX/AX/AL] = t[dst] -- yes late-night coding again
		 * and I'm really tired to comment this crap...
		 */
		case XED_ICLASS_CMPXCHG:
			/* both operands are registers */
			if (INS_MemoryOperandCount(ins) == 0) {
				/* extract the operands */
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);

				/* 32-bit operands */
				if (REG_is_gr32(reg_dst)) {
				/* propagate tag accordingly; fast path */
					INS_InsertIfCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opl_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_REG_VALUE, REG_EAX,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_REG_VALUE, reg_dst,
						IARG_END);
				/* propagate tag accordingly; slow path */
					INS_InsertThenCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opl_slow),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_END);
				}
				/* 16-bit operands */
				else if (REG_is_gr16(reg_dst)) {
				/* propagate tag accordingly; fast path */
					INS_InsertIfCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opw_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_REG_VALUE, REG_AX,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_REG_VALUE, reg_dst,
						IARG_END);
				/* propagate tag accordingly; slow path */
					INS_InsertThenCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opw_slow),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_END);
				}
				/* 8-bit operands */
				else
				warnx("%s:%u: unhandled opcode(opcode=%d)",
						__func__, __LINE__, ins_indx);
			}
			/* 1st operand is memory */
			else {
				/* extract the operand */
				reg_src = INS_OperandReg(ins, OP_1);

				/* 32-bit operands */
				if (REG_is_gr32(reg_src)) {
				/* propagate tag accordingly; fast path */
					INS_InsertIfCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_xfer_opl_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_REG_VALUE, REG_EAX,
						IARG_MEMORYREAD_EA,
						IARG_END);
				/* propagate tag accordingly; slow path */
					INS_InsertThenCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_xfer_opl_slow),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_END);
				}
				/* 16-bit operands */
				else if (REG_is_gr16(reg_src)) {
				/* propagate tag accordingly; fast path */
					INS_InsertIfCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_xfer_opw_fast),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_REG_VALUE, REG_AX,
						IARG_MEMORYREAD_EA,
						IARG_END);
				/* propagate tag accordingly; slow path */
					INS_InsertThenCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_xfer_opw_slow),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_END);
				}
				/* 8-bit operands */
				else
				warnx("%s:%u: unhandled opcode(opcode=%d)",
						__func__, __LINE__, ins_indx);
			}

			/* done */
			break;
		/* 
		 * xchg;
		 * exchange the tag information of the two operands
		 */
		case XED_ICLASS_XCHG:
			/* both operands are registers */
			if (INS_MemoryOperandCount(ins) == 0) {
				/* extract the operands */
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst)) {
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_UINT32, 8,
						IARG_END);
				}
				/* 16-bit operands */
				else if (REG_is_gr16(reg_dst)) { 
					/* propagate tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_UINT32, 8,
						IARG_END);
				}
				/* 8-bit operands */
				else if (REG_is_gr8(reg_dst)) {
					/* propagate tag accordingly */
					if (REG_is_Lower8(reg_dst) &&
						REG_is_Lower8(reg_src)) {
						/* lower 8-bit registers */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, 0,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_UINT32, 0,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_UINT32, 8,
						IARG_UINT32, 0,
						IARG_END);
					}
					else if(REG_is_Upper8(reg_dst) &&
						REG_is_Upper8(reg_src)) {
						/* upper 8-bit registers */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, 1,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_UINT32, 1,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_UINT32, 8,
						IARG_UINT32, 1,
						IARG_END);
					}
					else if (REG_is_Lower8(reg_dst)) {
						/* 
						 * destination register is a
						 * lower 8-bit register and
						 * source register is an upper
						 * 8-bit register
						 */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, 0,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb_lu),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb_ul),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_UINT32, 8,
						IARG_END);
					}
					else {
						/* 
						 * destination register is an
						 * upper 8-bit register and
						 * source register is a lower
						 * 8-bit register
						 */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, 1,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb_ul),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb_lu),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_UINT32, 8,
						IARG_END);
					}
				}
			}
			/* 
			 * 2nd operand is memory;
			 * we optimize for that case, since most
			 * instructions will have a register as
			 * the first operand -- leave the result
			 * into the reg and use it later
			 */
			else if (INS_OperandIsMemory(ins, OP_1)) {
				/* extract the register operand */
				reg_dst = INS_OperandReg(ins, OP_0);
				
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst)) {
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYREAD_EA,
						IARG_UINT32, 8,
						IARG_END);
				}
				/* 16-bit operands */
				else if (REG_is_gr16(reg_dst)) {
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYREAD_EA,
						IARG_UINT32, 8,
						IARG_END);
				}
				/* 8-bit operands */
				else {
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
						IARG_UINT32, REG8_INDX(reg_dst),
					IARG_UINT32, REG_is_Upper8(reg_dst),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
					IARG_UINT32, REG_is_Upper8(reg_dst),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYREAD_EA,
						IARG_UINT32, 8,
					IARG_UINT32, REG_is_Upper8(reg_dst),
						IARG_END);
				}
			}
			/* 1st operand is memory */
			else {
				/* extract the register operand */
				reg_src = INS_OperandReg(ins, OP_1);

				/* 32-bit operands */
				if (REG_is_gr32(reg_src)) {
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
						IARG_MEMORYWRITE_EA,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_UINT32, 8,
						IARG_END);
				}
				/* 16-bit operands */
				else if (REG_is_gr16(reg_src)) {
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
						IARG_MEMORYWRITE_EA,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_UINT32, 8,
						IARG_END);
				}
				/* 8-bit operands */
				else {
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG_is_Upper8(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG8_INDX(reg_src),
					IARG_UINT32, REG_is_Upper8(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_UINT32, 8,
					IARG_UINT32, REG_is_Upper8(reg_src),
						IARG_END);
				}
			}

			/* done */
			break;
		/* 
		 * xadd;
		 * xchg + add. We instrument this instruction  using the tag
		 * logic of xchg and add (see above)
		 */
		case XED_ICLASS_XADD:
			/* both operands are registers */
			if (INS_MemoryOperandCount(ins) == 0) {
				/* extract the operands */
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst)) {
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_UINT32, 8,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_END);
				}
				/* 16-bit operands */
				else if (REG_is_gr16(reg_dst)) { 
					/* propagate tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_UINT32, 8,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_END);
				}
				/* 8-bit operands */
				else if (REG_is_gr8(reg_dst)) {
					/* propagate tag accordingly */
					if (REG_is_Lower8(reg_dst) &&
						REG_is_Lower8(reg_src)) {
						/* lower 8-bit registers */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, 0,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_UINT32, 0,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_UINT32, 8,
						IARG_UINT32, 0,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_UINT32, 0,
						IARG_END);
					}
					else if(REG_is_Upper8(reg_dst) &&
						REG_is_Upper8(reg_src)) {
						/* upper 8-bit registers */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, 1,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_UINT32, 1,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_UINT32, 8,
						IARG_UINT32, 1,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_UINT32, 1,
						IARG_END);
					}
					else if (REG_is_Lower8(reg_dst)) {
						/* 
						 * destination register is a
						 * lower 8-bit register and
						 * source register is an upper
						 * 8-bit register
						 */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, 0,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb_lu),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb_ul),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_UINT32, 8,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opb_lu),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_END);
					}
					else {
						/* 
						 * destination register is an
						 * upper 8-bit register and
						 * source register is a lower
						 * 8-bit register
						 */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, 1,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb_ul),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb_lu),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_UINT32, 8,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opb_ul),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_END);
					}
				}
			}
			/* 1st operand is memory */
			else {
				/* extract the register operand */
				reg_src = INS_OperandReg(ins, OP_1);

				/* 32-bit operands */
				if (REG_is_gr32(reg_src)) {
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
						IARG_MEMORYWRITE_EA,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_UINT32, 8,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_binary_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_END);
				}
				/* 16-bit operands */
				else if (REG_is_gr16(reg_src)) {
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
						IARG_MEMORYWRITE_EA,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_UINT32, 8,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_binary_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_END);
				}
				/* 8-bit operands */
				else {
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG_is_Upper8(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG8_INDX(reg_src),
					IARG_UINT32, REG_is_Upper8(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_UINT32, 8,
					IARG_UINT32, REG_is_Upper8(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_binary_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG32_INDX(reg_src),
					IARG_UINT32, REG_is_Upper8(reg_src),
						IARG_END);
				}
			}

			/* done */
			break;
		/* xlat; similar to a mov between a memory location and AL */
		case XED_ICLASS_XLAT:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(m2r_xfer_opb),
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG8_INDX(REG_AL),
				IARG_MEMORYREAD_EA,
				IARG_UINT32, 0,
				IARG_END);

			/* done */
			break;
		/* lodsb; similar to a mov between a memory location and AL */
		case XED_ICLASS_LODSB:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(m2r_xfer_opb),
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG8_INDX(REG_AL),
				IARG_MEMORYREAD_EA,
				IARG_UINT32, 0,
				IARG_END);

			/* done */
			break;
		/* lodsw; similar to a mov between a memory location and AX */
		case XED_ICLASS_LODSW:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(m2r_xfer_opw),
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG16_INDX(REG_AX),
				IARG_MEMORYREAD_EA,
				IARG_END);

			/* done */
			break;
		/* lodsd; similar to a mov between a memory location and EAX */
		case XED_ICLASS_LODSD:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(m2r_xfer_opl),
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG32_INDX(REG_EAX),
				IARG_MEMORYREAD_EA,
				IARG_END);

			/* done */
			break;
		/* 
		 * stosb;
		 * the opposite of lodsb; however, since the instruction can
		 * also be prefixed with 'rep', the analysis code moves the
		 * tag information, accordingly, only once (i.e., before the
		 * first repetition) -- typically this will not lead in
		 * inlined code
		 */
		case XED_ICLASS_STOSB:
			/* the instruction is rep prefixed */
			if (INS_RepPrefix(ins)) {
				/* propagate the tag accordingly */
				INS_InsertIfPredicatedCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(rep_predicate),
					IARG_FAST_ANALYSIS_CALL,
					IARG_FIRST_REP_ITERATION,
					IARG_END);
				INS_InsertThenPredicatedCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(r2m_xfer_opbn),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
				IARG_REG_VALUE, INS_OperandReg(ins, OP_3),
					IARG_END);
			}
			/* no rep prefix */
			else 
				/* the instruction is not rep prefixed */
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(r2m_xfer_opb),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG8_INDX(REG_AL),
					IARG_UINT32, 0,
					IARG_END);

			/* done */
			break;
		/* 
		 * stosw; 
		 * the opposite of lodsw; however, since the instruction can
		 * also be prefixed with 'rep', the analysis code moves the
		 * tag information, accordingly, only once (i.e., before the
		 * first repetition) -- typically this will not lead in
		 * inlined code
		 */
		case XED_ICLASS_STOSW:
			/* the instruction is rep prefixed */
			if (INS_RepPrefix(ins)) {
				/* propagate the tag accordingly */
				INS_InsertIfPredicatedCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(rep_predicate),
					IARG_FAST_ANALYSIS_CALL,
					IARG_FIRST_REP_ITERATION,
					IARG_END);
				INS_InsertThenPredicatedCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(r2m_xfer_opwn),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
				IARG_REG_VALUE, INS_OperandReg(ins, OP_3),
					IARG_END);
			}
			/* no rep prefix */
			else
				/* the instruction is not rep prefixed */
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(r2m_xfer_opw),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG16_INDX(REG_AX),
					IARG_END);

			/* done */
			break;
		/* 
		 * stosd;
		 * the opposite of lodsd; however, since the instruction can
		 * also be prefixed with 'rep', the analysis code moves the
		 * tag information, accordingly, only once (i.e., before the
		 * first repetition) -- typically this will not lead in
		 * inlined code
		 */
		case XED_ICLASS_STOSD:
			/* the instruction is rep prefixed */
			if (INS_RepPrefix(ins)) {
				/* propagate the tag accordingly */
				INS_InsertIfPredicatedCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(rep_predicate),
					IARG_FAST_ANALYSIS_CALL,
					IARG_FIRST_REP_ITERATION,
					IARG_END);
				INS_InsertThenPredicatedCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(r2m_xfer_opln),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
				IARG_REG_VALUE, INS_OperandReg(ins, OP_3),
					IARG_END);
			}
			/* no rep prefix */
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(r2m_xfer_opl),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG32_INDX(REG_EAX),
					IARG_END);

			/* done */
			break;
		/* movsd */
		case XED_ICLASS_MOVSD:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(m2m_xfer_opl),
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_MEMORYREAD_EA,
				IARG_END);

			/* done */
			break;
		/* movsw */
		case XED_ICLASS_MOVSW:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(m2m_xfer_opw),
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_MEMORYREAD_EA,
				IARG_END);

			/* done */
			break;
		/* movsb */
		case XED_ICLASS_MOVSB:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(m2m_xfer_opb),
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_MEMORYREAD_EA,
				IARG_END);

			/* done */
			break;
		/* rcl */
		case XED_ICLASS_RCL:
		/* rcr */
		case XED_ICLASS_RCR:
		/* rol */
		case XED_ICLASS_ROL:
		/* ror */
		case XED_ICLASS_ROR:
		/* sal */
		case XED_ICLASS_SALC:
		/* sar */
		case XED_ICLASS_SAR:
		/* shl */
		case XED_ICLASS_SHL:
		/* shr */
		case XED_ICLASS_SHR:
			/*
			 * the general format of these instructions
			 * is the following: dst {op}= src, where
			 * op can be <<, >>, etc. We tag the
			 * destination if the source is also taged
			 * (i.e., t[dst] |= t[src]); we also extend
			 * the tag bits accordingly (e.g., 8-bit
			 * to 16-bit, 16-bit to 32-bit, etc)
			 */
			/* 2nd operand is immediate; do nothing */
			if (INS_OperandIsImmediate(ins, OP_1))
				break;

			/* 1st operand is register */
			if (INS_MemoryOperandCount(ins) == 0) {
				/* extract the operand */
				reg_dst = INS_OperandReg(ins, OP_0);
				
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_oplb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_END);
				/* 16-bit operands */
				else if (REG_is_gr16(reg_dst))
					/* propagate tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opwb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_END);
				/* 8-bit operands */
				else {
					/* propagate tag accordingly */
					if (REG_is_Lower8(reg_dst))
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(r2r_binary_opb),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(REG_CL),
							IARG_UINT32, 0,
							IARG_END);
					else if(REG_is_Upper8(reg_dst))
						INS_InsertCall(ins,
							IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opb_ul),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(REG_CL),
						IARG_END);
				}
			}
			/* 1st operand is memory */
			else {
				/* 32-bit operand */
				if(INS_MemoryWriteSize(ins) ==
						BIT2BYTE(MEM_LONG_LEN))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_binary_oplb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_END);
				/* 16-bit operand */
				else if (INS_MemoryWriteSize(ins) ==
						BIT2BYTE(MEM_WORD_LEN))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_binary_opwb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_END);
				/* 8-bit operand */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_binary_opb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG8_INDX(REG_CL),
					IARG_UINT32, 0,
						IARG_END);
			}

			/* done */
			break;
		/* shld */
		case XED_ICLASS_SHLD:
		/* shrd */
		case XED_ICLASS_SHRD:
			/*
			 * the general format of these instructions
			 * is the following: dst {op}= src1, src2,
			 * where op can be <<, >>, etc. We tag the
			 * destination if the sources are also taged
			 * (i.e., t[dst] |= (t[src1] | t[src2)])
			 */
			/* 3rd operand is immediate */
			if (INS_OperandIsImmediate(ins, OP_2)) {
				/*
				 * both operands (i.e., 1st & 2nd) are
				 * registers
				 */
				if (INS_MemoryOperandCount(ins) == 0) {
					/* extract the operands */
					reg_dst = INS_OperandReg(ins, OP_0);
					reg_src = INS_OperandReg(ins, OP_1);
				
					/* 32-bit operands */
					if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_END);
					/* 16-bit operands */
					else
					/* propagate tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_END);
				}
				/* 1st operand is memory */
				else {
					/* extract the source operand */
					reg_src = INS_OperandReg(ins, OP_1);
				
					/* 32-bit operand operand */
					if (REG_is_gr32(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_binary_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_END);
					/* 16-bit operand */
					else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_binary_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_END);
				}

				/* done */
				break;
			}
			
			/*
			 * both operands are registers; the third operand is
			 * not an immediate value
			 */
			if (INS_MemoryOperandCount(ins) == 0) {
				/* extract the operands */
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);

				/* 32-bit operands */
				if (REG_is_gr32(reg_dst)) {
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r_clrl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_oplb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_UINT32, 8,
						IARG_END);
				}
				/* 16-bit operands */
				else {
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r_clrl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opwb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_UINT32, 8,
						IARG_END);
				}
			}
			/* 1st operand is memory */
			else {
				/* extract the source operand */
				reg_src = INS_OperandReg(ins, OP_1);

				/* 32-bit operands */
				if (REG_is_gr32(reg_src)) {
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r_clrl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_oplb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_binary_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 8,
						IARG_END);
				}
				/* 16-bit operands */
				else {
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r_clrl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opwb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 8,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_binary_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 8,
						IARG_END);
				}
			}

			/* done */
			break;
		/* pop; mov equivalent (see above) */
		case XED_ICLASS_POP:
			/* register operand */
			if (INS_OperandIsReg(ins, OP_0)) {
				/* extract the operand */
				reg_dst = INS_OperandReg(ins, OP_0);

				/* 32-bit operand */
				if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				/* 16-bit operand */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2r_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
			}
			/* memory operand */
			else if (INS_OperandIsMemory(ins, OP_0)) {
				/* 32-bit operand */
				if (INS_MemoryWriteSize(ins) ==
						BIT2BYTE(MEM_LONG_LEN))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2m_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYREAD_EA,
						IARG_END);
				/* 16-bit operand */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2m_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYREAD_EA,
						IARG_END);
			}
			/* 
			 * we don't have to do something in case the 
			 * destination operand is a segment register
			 */

			/* done */
			break;
		/* push; mov equivalent (see above) */
		case XED_ICLASS_PUSH:
			/* register operand */
			if (INS_OperandIsReg(ins, OP_0)) {
				/* extract the operand */
				reg_src = INS_OperandReg(ins, OP_0);

				/* 32-bit operand */
				if (REG_is_gr32(reg_src))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG32_INDX(reg_src),
						IARG_END);
				/* 16-bit operand */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2m_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG16_INDX(reg_src),
						IARG_END);
			}
			/* memory operand */
			else if (INS_OperandIsMemory(ins, OP_0)) {
				/* 32-bit operand */
				if (INS_MemoryWriteSize(ins) ==
						BIT2BYTE(MEM_LONG_LEN))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2m_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYREAD_EA,
						IARG_END);
				/* 16-bit operand */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(m2m_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYREAD_EA,
						IARG_END);
			}
			/* immediate or segment operand; clean */
			else {
				/* clear n-bytes */
				switch (INS_OperandWidth(ins, OP_0)) {
					/* 4 bytes */
					case MEM_LONG_LEN:
				/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(tagmap_clrl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);

						/* done */
						break;
					/* 2 bytes */
					case MEM_WORD_LEN:
				/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(tagmap_clrw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);

						/* done */
						break;
					/* 1 byte */
					case MEM_BYTE_LEN:
				/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(tagmap_clrb),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);

						/* done */
						break;
					/* make the compiler happy */
					default:
						/* done */
						break;
				}
			}

			/* done */
			break;
		/* popa;
		 * similar to pop but for all the 16-bit
		 * general purpose registers
		 */
		case XED_ICLASS_POPA:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(m2r_restore_opw),
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_MEMORYREAD_EA,
				IARG_END);

			/* done */
			break;
		/* popad; 
		 * similar to pop but for all the 32-bit
		 * general purpose registers
		 */
		case XED_ICLASS_POPAD:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(m2r_restore_opl),
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_MEMORYREAD_EA,
				IARG_END);

			/* done */
			break;
		/* pusha; 
		 * similar to push but for all the 16-bit
		 * general purpose registers
		 */
		case XED_ICLASS_PUSHA:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(r2m_save_opw),
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_MEMORYWRITE_EA,
				IARG_END);

			/* done */
			break;
		/* pushad; 
		 * similar to push but for all the 32-bit
		 * general purpose registers
		 */
		case XED_ICLASS_PUSHAD:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(r2m_save_opl),
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_MEMORYWRITE_EA,
				IARG_END);

			/* done */
			break;
		/* pushf; clear a memory word (i.e., 16-bits) */
		case XED_ICLASS_PUSHF:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(tagmap_clrw),
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_END);

			/* done */
			break;
		/* pushfd; clear a double memory word (i.e., 32-bits) */
		case XED_ICLASS_PUSHFD:
			/* propagate the tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				AFUNPTR(tagmap_clrl),
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_END);

			/* done */
			break;
		/* call (near); similar to push (see above) */
		case XED_ICLASS_CALL_NEAR:
			/* relative target */
			if (INS_OperandIsImmediate(ins, OP_0)) {
				/* 32-bit operand */
				if (INS_OperandWidth(ins, OP_0) == MEM_LONG_LEN) {
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(tagmap_clrl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(tagmap_getl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYREAD_EA,
						IARG_END);
				}
				/* 16-bit operand */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(tagmap_clrw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);
			}
			/* absolute target; register */
			else if (INS_OperandIsReg(ins, OP_0)) {
				/* extract the source register */
				reg_src = INS_OperandReg(ins, OP_0);

				/* 32-bit operand */
				if (REG_is_gr32(reg_src)) {
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(tagmap_clrl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(tagmap_getl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);
				}
				/* 16-bit operand */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(tagmap_clrw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);
			}
			/* absolute target; memory */
			else {
				/* 32-bit operand */
				if (INS_OperandWidth(ins, OP_0) == MEM_LONG_LEN) {
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(tagmap_clrl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);

					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(tagmap_getl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);

				}
				/* 16-bit operand */
				else
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(tagmap_clrw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);
			}

			/* done */
			break;
		/* 
		 * leave;
		 * similar to a mov between ESP/SP and EBP/BP, and a pop
		 */
		case XED_ICLASS_LEAVE:
			/* extract the operands */
			reg_dst = INS_OperandReg(ins, OP_3);
			reg_src = INS_OperandReg(ins, OP_2);

			/* 32-bit operands */	
			if (REG_is_gr32(reg_dst)) {
				/* propagate the tag accordingly */
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(r2r_xfer_opl),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_src),
					IARG_END);
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(m2r_xfer_opl),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_src),
					IARG_MEMORYREAD_EA,
					IARG_END);
			}
			/* 16-bit operands */
			else {
				/* propagate the tag accordingly */
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(r2r_xfer_opw),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
					IARG_END);
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(m2r_xfer_opw),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_src),
					IARG_MEMORYREAD_EA,
					IARG_END);
			}

			/* done */
			break;
		/* lea */
		case XED_ICLASS_LEA:
			/*
			 * the general format of this instruction
			 * is the following: dst = src_base | src_indx.
			 * We move the tags of the source base and index
			 * registers to the destination
			 * (i.e., t[dst] = t[src_base] | t[src_indx])
			 */

			/* extract the operands */
			reg_base	= INS_MemoryBaseReg(ins);
			reg_indx	= INS_MemoryIndexReg(ins);
			reg_dst		= INS_OperandReg(ins, OP_0);
			
			/* no base or index register; clear the destination */
			if (reg_base == REG_INVALID() &&
					reg_indx == REG_INVALID()) {
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst))
					/* clear */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r_clrl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32,
						REG32_INDX(reg_dst),
						IARG_END);
				/* 16-bit operands */
				else 
					/* clear */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r_clrw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32,
						REG16_INDX(reg_dst),
						IARG_END);
			}
			/* base register exists; no index register */
			if (reg_base != REG_INVALID() &&
					reg_indx == REG_INVALID()) {
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_base),
						IARG_END);
				/* 16-bit operands */
				else 
					/* propagate tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_base),
						IARG_END);
			}
			/* index register exists; no base register */
			if (reg_base == REG_INVALID() &&
					reg_indx != REG_INVALID()) {
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst))
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_indx),
						IARG_END);
				/* 16-bit operands */
				else
					/* propagate tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_indx),
						IARG_END);
			}
			/* base and index registers exist */
			if (reg_base != REG_INVALID() &&
					reg_indx != REG_INVALID()) {
				/* 32-bit operands */
				if (REG_is_gr32(reg_dst)) {
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, 8,
					IARG_UINT32, REG32_INDX(reg_base),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, 8,
					IARG_UINT32, REG32_INDX(reg_indx),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opl),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, 8,
						IARG_END);
				}
				/* 16-bit operands */
				else {
					/* propagate the tag accordingly */
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, 8,
					IARG_UINT32, REG16_INDX(reg_base),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_binary_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, 8,
					IARG_UINT32, REG16_INDX(reg_indx),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						AFUNPTR(r2r_xfer_opw),
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, 8,
						IARG_END);
				}
			}
			
			/* done */
			break;
		/* call; far */
		case XED_ICLASS_CALL_FAR:
		/* cmpxchg */
		case XED_ICLASS_CMPXCHG8B:
		/* enter */
		case XED_ICLASS_ENTER:
		/* lds */
		case XED_ICLASS_LDS:
		/* lss */
		case XED_ICLASS_LSS:
		/* les */
		case XED_ICLASS_LES:
		/* lfs */
		case XED_ICLASS_LFS:
		/* lgs */
		case XED_ICLASS_LGS:
			warnx("%s:%u: unhandled opcode(opcode=%d)",
					__func__, __LINE__, ins_indx);

			/* done */
			break;
		/* 
		 * default handler
		 */
		default:
			/*(void)fprintf(stdout, "%s\n",
				INS_Disassemble(ins).c_str());*/
			break;
	}
}
