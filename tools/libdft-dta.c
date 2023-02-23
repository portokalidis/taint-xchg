/*-
 * Copyright (c) 2010, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in October 2010.
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

#include <err.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>

#include <set>

#include "branch_pred.h"
#include "libdft_api.h"
#include "libdft_core.h"
#include "syscall_desc.h"
#include "tagmap.h"

#define WORD_LEN	4	/* size in bytes of a word value */
#define SYS_SOCKET	1	/* socket(2) demux index for socketcall */
				/* default path for the log file (audit) */
#define LOGFILE_DFL	"/tmp/libdft-dta.log"

/* threads context */
extern thread_ctx_t *threads_ctx;

/* ins descriptors */
extern ins_desc_t ins_desc[XED_ICLASS_LAST];

/* syscall descriptors */
extern syscall_desc_t syscall_desc[SYSCALL_MAX];

/* set of interesting descriptors (sockets) */
static set<int> fdset;

/* log file path (auditing) */
KNOB<string> logpath(KNOB_MODE_WRITEONCE, "pintool", "o", LOGFILE_DFL, "");

/* 
 * DTA/DFT alert
 *
 * @ins:	address of the offending instruction
 * @bt:		address of the branch target
 */
static void PIN_FAST_ANALYSIS_CALL
alert(ADDRINT ins, ADDRINT bt)
{
	/* log file */
	FILE *logfile;

	/* auditing */
	if (likely((logfile = fopen(logpath.Value().c_str(), "a")) != NULL)) {
		/* hilarious :) */
		(void)fprintf(logfile, " ____ ____ ____ ____\n");
		(void)fprintf(logfile, "||w |||o |||o |||t ||\n");
		(void)fprintf(logfile, "||__|||__|||__|||__||\t");
		(void)fprintf(logfile, "[%d]: 0x%08x --> 0x%08x\n",
							getpid(), ins, bt);

		(void)fprintf(logfile, "|/__\\|/__\\|/__\\|/__\\|\n");
		
		/* cleanup */
		(void)fclose(logfile);
	}
	else
		/* failed */
		warnx("%s:%u: failed while trying to open the log(%s)",
				__func__, __LINE__, logpath.Value().c_str());

	/* terminate */
	exit(EXIT_FAILURE);
}

/*
 * 32-bit register assertion (taint-sink, DFT-sink)
 *
 * called before an instruction that uses a register
 * for an indirect branch; returns a positive value
 * whenever the register value or the target address
 * are tainted
 *
 * returns:	0 (clean), >0 (tainted)
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
assert_reg32(THREADID tid, uint32_t reg, uint32_t addr)
{
	/* 
	 * combine the register tag along with the tag
	 * markings of the target address
	 */
	return threads_ctx[tid].vcpu.gpr[reg] | tagmap_getl(addr);
}

/*
 * 16-bit register assertion (taint-sink, DFT-sink)
 *
 * called before an instruction that uses a register
 * for an indirect branch; returns a positive value
 * whenever the register value or the target address
 * are tainted
 *
 * returns:	0 (clean), >0 (tainted)
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
assert_reg16(THREADID tid, uint32_t reg, uint32_t addr)
{
	/* 
	 * combine the register tag along with the tag
	 * markings of the target address
	 */
	return (threads_ctx[tid].vcpu.gpr[reg] & VCPU_MASK16)
		| tagmap_getw(addr);
}

/*
 * 32-bit memory assertion (taint-sink, DFT-sink)
 *
 * called before an instruction that uses a memory
 * location for an indirect branch; returns a positive
 * value whenever the memory value (i.e., effective address),
 * or the target address, are tainted
 *
 * returns:	0 (clean), >0 (tainted)
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
assert_mem32(ADDRINT paddr, ADDRINT taddr)
{
	return tagmap_getl(paddr) | tagmap_getl(taddr);
}

/*
 * 16-bit memory assertion (taint-sink, DFT-sink)
 *
 * called before an instruction that uses a memory
 * location for an indirect branch; returns a positive
 * value whenever the memory value (i.e., effective address),
 * or the target address, are tainted
 *
 * returns:	0 (clean), >0 (tainted)
 */
static ADDRINT PIN_FAST_ANALYSIS_CALL
assert_mem16(ADDRINT paddr, ADDRINT taddr)
{
	return tagmap_getw(paddr) | tagmap_getw(taddr);
}

/*
 * instrument the jmp/call instructions
 *
 * install the appropriate DTA/DFT logic (sinks)
 *
 * @ins:	the instruction to instrument
 */
static void
dta_instrument_jmp_call(INS ins)
{
	/* temporaries */
	REG reg;

	/* 
	 * we only care about indirect calls;
	 * optimized branch
	 */
	if (unlikely(INS_IsIndirectBranchOrCall(ins))) {
		/* perform operand analysis */

		/* call via register */
		if (INS_OperandIsReg(ins, 0)) {
			/* extract the register from the instruction */
			reg = INS_OperandReg(ins, 0);

			/* size analysis */

			/* 32-bit register */
			if (REG_is_gr32(reg))
				/*
				 * instrument assert_reg32() before call;
				 * conditional instrumentation -- if
				 */
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(assert_reg32),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg),
					IARG_REG_VALUE, reg,
					IARG_END);
			else
				/* 16-bit register */
				/*
				 * instrument assert_reg16() before call;
				 * conditional instrumentation -- if
				 */
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(assert_reg16),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg),
					IARG_REG_VALUE, reg,
					IARG_END);
		}
		else {
		/* call via memory */
			/* size analysis */
				
			/* 32-bit */
			if (INS_MemoryReadSize(ins) == WORD_LEN)
				/*
				 * instrument assert_mem32() before call;
				 * conditional instrumentation -- if
				 */
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(assert_mem32),
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYREAD_EA,
					IARG_BRANCH_TARGET_ADDR,
					IARG_END);
			/* 16-bit */
			else
				/*
				 * instrument assert_mem16() before call;
				 * conditional instrumentation -- if
				 */
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(assert_mem16),
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYREAD_EA,
					IARG_BRANCH_TARGET_ADDR,
					IARG_END);
		}
		/*
		 * instrument alert() before call;
		 * conditional instrumentation -- then
		 */
		INS_InsertThenCall(ins,
			IPOINT_BEFORE,
			AFUNPTR(alert),
			IARG_FAST_ANALYSIS_CALL,
			IARG_INST_PTR,
			IARG_BRANCH_TARGET_ADDR,
			IARG_END);
	}
}

/*
 * instrument the conditional jmp instructions
 *
 * install the appropriate DTA/DFT logic (sinks)
 *
 * @ins:	the instruction to instrument
 */
static void
dta_instrument_cjmp(INS ins)
{
	/* temporaries */
	REG reg;

	/* 
	 * we only care about indirect calls;
	 * optimized branch
	 */
	if (unlikely(INS_IsIndirectBranchOrCall(ins))) {
		/* perform operand analysis */

		/* call via register */
		if (INS_OperandIsReg(ins, 0)) {
			/* extract the register from the instruction */
			reg = INS_OperandReg(ins, 0);

			/* size analysis */

			/* 32-bit register */
			if (REG_is_gr32(reg))
				/*
				 * instrument assert_reg32() before call;
				 * conditional instrumentation -- if predicated
				 */
				INS_InsertIfPredicatedCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(assert_reg32),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG32_INDX(reg),
					IARG_REG_VALUE, reg,
					IARG_END);
			else
				/* 16-bit register */
				/*
				 * instrument assert_reg16() before call;
				 * conditional instrumentation -- if predicated
				 */
				INS_InsertIfPredicatedCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(assert_reg16),
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG16_INDX(reg),
					IARG_REG_VALUE, reg,
					IARG_END);
		}
		else {
		/* call via memory */
			/* operand analysis */

			/* size analysis */
				
			/* 32-bit */
			if (INS_MemoryReadSize(ins) == WORD_LEN)
				/*
				 * instrument assert_mem32() before call;
				 * conditional instrumentation -- if predicated
				 */
				INS_InsertIfPredicatedCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(assert_mem32),
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYREAD_EA,
					IARG_BRANCH_TARGET_ADDR,
					IARG_END);
			/* 16-bit */
			else
				/*
				 * instrument assert_mem16() before call;
				 * conditional instrumentation -- if predicated
				 */
				INS_InsertIfPredicatedCall(ins,
					IPOINT_BEFORE,
					AFUNPTR(assert_mem16),
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYREAD_EA,
					IARG_BRANCH_TARGET_ADDR,
					IARG_END);
		}
		/*
		 * instrument alert() before call;
		 * conditional instrumentation -- then predicated
		 */
		INS_InsertThenPredicatedCall(ins,
			IPOINT_BEFORE,
			AFUNPTR(alert),
			IARG_FAST_ANALYSIS_CALL,
			IARG_INST_PTR,
			IARG_BRANCH_TARGET_ADDR,
			IARG_END);
	}
}

/*
 * instrument the ret instruction
 *
 * install the appropriate DTA/DFT logic (sinks)
 *
 * @ins:	the instruction to instrument
 */
static void
dta_instrument_ret(INS ins)
{
	/* size analysis */
				
	/* 32-bit */
	if (INS_MemoryReadSize(ins) == WORD_LEN)
		/*
		 * instrument assert_mem32() before call;
		 * conditional instrumentation -- if
		 */
		INS_InsertIfCall(ins,
			IPOINT_BEFORE,
			AFUNPTR(assert_mem32),
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYREAD_EA,
			IARG_BRANCH_TARGET_ADDR,
			IARG_END);
	/* 16-bit */
	else
		/*
		 * instrument assert_mem16() before call;
		 * conditional instrumentation -- if
		 */
		INS_InsertIfCall(ins,
			IPOINT_BEFORE,
			AFUNPTR(assert_mem16),
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYREAD_EA,
			IARG_BRANCH_TARGET_ADDR,
			IARG_END);
	
	/*
	 * instrument alert() before call;
	 * conditional instrumentation -- then
	 */
	INS_InsertThenCall(ins,
		IPOINT_BEFORE,
		AFUNPTR(alert),
		IARG_FAST_ANALYSIS_CALL,
		IARG_INST_PTR,
		IARG_BRANCH_TARGET_ADDR,
		IARG_END);
}

/*
 * read(2) handler (taint-source)
 */
static void
post_read_hook(syscall_ctx_t *ctx)
{
        /* read() was not successful; optimized branch */
        if (unlikely((long)ctx->ret <= 0))
                return;

	/* taint-source */
	if (fdset.find(ctx->arg[SYSCALL_ARG0]) != fdset.end())
        	/* set the tag markings */
	        tagmap_setn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
	else
        	/* clear the tag markings */
	        tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
}

/*
 * readv(2) handler (taint-source)
 */
static void
post_readv_hook(syscall_ctx_t *ctx)
{
	/* iterators */
	int i;
	struct iovec *iov;
	set<int>::iterator it;

	/* bytes copied in a iovec structure */
	size_t iov_tot;

	/* total bytes copied */
	size_t tot = (size_t)ctx->ret;

	/* readv() was not successful; optimized branch */
	if (unlikely((long)ctx->ret <= 0))
		return;
	
	/* get the descriptor */
	it = fdset.find((int)ctx->arg[SYSCALL_ARG0]);

	/* iterate the iovec structures */
	for (i = 0; i < (int)ctx->arg[SYSCALL_ARG2] && tot > 0; i++) {
		/* get an iovec  */
		iov = ((struct iovec *)ctx->arg[SYSCALL_ARG1]) + i;
		
		/* get the length of the iovec */
		iov_tot = (tot >= (size_t)iov->iov_len) ?
			(size_t)iov->iov_len : tot;
	
		/* taint interesting data and zero everything else */	
		if (it != fdset.end())
                	/* set the tag markings */
                	tagmap_setn((size_t)iov->iov_base, iov_tot);
		else
                	/* clear the tag markings */
                	tagmap_clrn((size_t)iov->iov_base, iov_tot);

                /* housekeeping */
                tot -= iov_tot;
        }
}

/*
 * socketcall(2) handler
 *
 * attach taint-sources in the following
 * syscalls:
 * 	socket(2), accept(2), recv(2),
 * 	recvfrom(2), recvmsg(2)
 *
 * everything else is left intact in order
 * to avoid taint-leaks
 */
static void
post_socketcall_hook(syscall_ctx_t *ctx)
{
	/* message header; recvmsg(2) */
	struct msghdr *msg;

	/* iov bytes copied; recvmsg(2) */
	size_t iov_tot;

	/* iterators */
	size_t i;
	struct iovec *iov;
	set<int>::iterator it;
	
	/* total bytes received */
	size_t tot;
	
	/* socket call arguments */
	unsigned long *args = (unsigned long *)ctx->arg[SYSCALL_ARG1];

	/* demultiplex the socketcall */
	switch ((int)ctx->arg[SYSCALL_ARG0]) {
		case SYS_SOCKET:
			/* not successful; optimized branch */
			if (unlikely((long)ctx->ret < 0))
				return;

			/*
			 * PF_INET and PF_INET6 descriptors are
			 * considered interesting
			 */
			if (likely(args[SYSCALL_ARG0] == PF_INET ||
				args[SYSCALL_ARG0] == PF_INET6))
				/* add the descriptor to the monitored set */
				fdset.insert((int)ctx->ret);

			/* done */
			break;
		case SYS_ACCEPT:
		case SYS_ACCEPT4:
			/* not successful; optimized branch */
			if (unlikely((long)ctx->ret < 0))
				return;
			/*
			 * if the socket argument is interesting,
			 * the returned handle of accept(2) is also
			 * interesting
			 */
			if (likely(fdset.find(args[SYSCALL_ARG0]) !=
						fdset.end()))
				/* add the descriptor to the monitored set */
				fdset.insert((int)ctx->ret);
		case SYS_GETSOCKNAME:
		case SYS_GETPEERNAME:
			/* not successful; optimized branch */
			if (unlikely((long)ctx->ret < 0))
				return;

			/* addr argument is provided */
			if ((void *)args[SYSCALL_ARG1] != NULL) {
				/* clear the tag bits */
				tagmap_clrn(args[SYSCALL_ARG1],
					*((int *)args[SYSCALL_ARG2]));
				
				/* clear the tag bits */
				tagmap_clrn(args[SYSCALL_ARG2], sizeof(int));
			}
			break;
		case SYS_SOCKETPAIR:
			/* not successful; optimized branch */
			if (unlikely((long)ctx->ret < 0))
				return;
	
			/* clear the tag bits */
			tagmap_clrn(args[SYSCALL_ARG3], (sizeof(int) * 2));
			break;
		case SYS_RECV:
			/* not successful; optimized branch */
			if (unlikely((long)ctx->ret <= 0))
				return;
			
			/* taint-source */	
			if (fdset.find((int)args[SYSCALL_ARG0]) != fdset.end())
				/* set the tag markings */
				tagmap_setn(args[SYSCALL_ARG1],
							(size_t)ctx->ret);
			else
				/* clear the tag markings */
				tagmap_clrn(args[SYSCALL_ARG1],
							(size_t)ctx->ret);
			break;
		case SYS_RECVFROM:
			/* not successful; optimized branch */
			if (unlikely((long)ctx->ret <= 0))
				return;
	
			/* taint-source */	
			if (fdset.find((int)args[SYSCALL_ARG0]) != fdset.end())
				/* set the tag markings */
				tagmap_setn(args[SYSCALL_ARG1],
						(size_t)ctx->ret);
			else
				/* clear the tag markings */
				tagmap_clrn(args[SYSCALL_ARG1],
						(size_t)ctx->ret);

			/* sockaddr argument is specified */
			if ((void *)args[SYSCALL_ARG4] != NULL) {
				/* clear the tag bits */
				tagmap_clrn(args[SYSCALL_ARG4],
					*((int *)args[SYSCALL_ARG5]));
				
				/* clear the tag bits */
				tagmap_clrn(args[SYSCALL_ARG5], sizeof(int));
			}
			break;
		case SYS_GETSOCKOPT:
			/* not successful; optimized branch */
			if (unlikely((long)ctx->ret < 0))
				return;
	
			/* clear the tag bits */
			tagmap_clrn(args[SYSCALL_ARG3],
					*((int *)args[SYSCALL_ARG4]));
			
			/* clear the tag bits */
			tagmap_clrn(args[SYSCALL_ARG4], sizeof(int));
			break;
		case SYS_RECVMSG:
			/* not successful; optimized branch */
			if (unlikely((long)ctx->ret <= 0))
				return;
			
			/* get the descriptor */
			it = fdset.find((int)ctx->arg[SYSCALL_ARG0]);

			/* extract the message header */
			msg = (struct msghdr *)args[SYSCALL_ARG1];

			/* source address specified */
			if (msg->msg_name != NULL)
				/* clear the tag bits */
				tagmap_clrn((size_t)msg->msg_name,
					msg->msg_namelen);
			
			/* ancillary data specified */
			if (msg->msg_control != NULL) {
				/* taint-source */
				if (it != fdset.end())
					/* set the tag markings */
					tagmap_setn((size_t)msg->msg_control,
						msg->msg_controllen);
				else
					/* clear the tag markings */
					tagmap_clrn((size_t)msg->msg_control,
						msg->msg_controllen);
			}
			
			/* total bytes received */	
			tot = (size_t)ctx->ret;

			/* iterate the iovec structures */
			for (i = 0; i < msg->msg_iovlen && tot > 0; i++) {
				/* get the next I/O vector */
				iov = &msg->msg_iov[i];

				/* get the length of the iovec */
				iov_tot = (tot > (size_t)iov->iov_len) ?
						(size_t)iov->iov_len : tot;
				
				/* taint-source */	
				if (it != fdset.end())
					/* set the tag markings */
					tagmap_setn((size_t)iov->iov_base,
								iov_tot);
				else
					/* clear the tag markings */
					tagmap_clrn((size_t)iov->iov_base,
								iov_tot);
		
				/* housekeeping */
				tot -= iov_tot;
			}
			break;
		case SYS_RECVMMSG:
		default:
			/* nothing to do */
			return;
	}
}

/*
 * auxiliary (helper) function
 *
 * duplicated descriptors are added into
 * the monitored set
 */
static void
post_dup_hook(syscall_ctx_t *ctx)
{
	/* not successful; optimized branch */
	if (unlikely((long)ctx->ret < 0))
		return;
	
	/*
	 * if the old descriptor argument is
	 * interesting, the returned handle is
	 * also interesting
	 */
	if (likely(fdset.find((int)ctx->arg[SYSCALL_ARG0]) != fdset.end()))
		fdset.insert((int)ctx->ret);
}

/*
 * auxiliary (helper) function
 *
 * whenever close(2) is invoked, check
 * the descriptor and remove if it was
 * inside the monitored set of descriptors
 */
static void
post_close_hook(syscall_ctx_t *ctx)
{
	/* iterator */
	set<int>::iterator it;

	/* not successful; optimized branch */
	if (unlikely((long)ctx->ret < 0))
		return;
	
	/*
	 * if the descriptor (argument) is
	 * interesting, remove it from the
	 * monitored set
	 */
	it = fdset.find((int)ctx->arg[SYSCALL_ARG0]);
	if (likely(it != fdset.end()))
		fdset.erase(it);
}


/* 
 * DTA
 *
 * used for demonstrating how to implement
 * a practical dynamic taint analysis (DTA)
 * tool using libdft
 */
int
main(int argc, char **argv)
{
	/* initialize the core tagging engine */
	if (unlikely(libdft_init(argc, argv) != 0))
		/* failed */
		goto err;
	
	/* 
	 * handle control transfer instructions
	 *
	 * instrument the branch instructions, accordingly,
	 * for installing taint-sinks (DFT-logic) that check
	 * for tainted targets (i.e., tainted operands or
	 * tainted branch targets) -- For brevity I omitted
	 * checking the result of each instrumentation for
	 * success or failure
	 */

	/* instrument call */
	(void)ins_set_post(&ins_desc[XED_ICLASS_CALL_NEAR],
			dta_instrument_jmp_call);
	
	/* instrument jmp */
	(void)ins_set_post(&ins_desc[XED_ICLASS_JMP],
			dta_instrument_jmp_call);

	/* instrument ret */
	(void)ins_set_post(&ins_desc[XED_ICLASS_RET_NEAR],
			dta_instrument_ret);

	/* instrument conditional branches */
	(void)ins_set_post(&ins_desc[XED_ICLASS_JB],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JBE],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JL],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JLE],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JNB],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JNBE],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JNL],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JNLE],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JNO],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JNP],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JNS],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JNZ],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JO],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JP],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JRCXZ],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JS],
			dta_instrument_cjmp);
	(void)ins_set_post(&ins_desc[XED_ICLASS_JZ],
			dta_instrument_cjmp);

	/* 
	 * install taint-sources
	 *
	 * all network-related I/O calls are
	 * assumed to be taint-sources; we
	 * install the appropriate wrappers
	 * for tagging the received data
	 * accordingly -- Again, for brevity
	 * I assume that all calls to
	 * syscall_set_post() are successful
	 */
	
	/* read(2) */
	(void)syscall_set_post(&syscall_desc[__NR_read], post_read_hook);

	/* readv(2) */
	(void)syscall_set_post(&syscall_desc[__NR_readv], post_readv_hook);

	/* socket(2), accept(2), recv(2), recvfrom(2), recvmsg(2) */
	(void)syscall_set_post(&syscall_desc[__NR_socketcall],
			post_socketcall_hook);

	/* dup(2), dup2(2) */
	(void)syscall_set_post(&syscall_desc[__NR_dup], post_dup_hook);
	(void)syscall_set_post(&syscall_desc[__NR_dup2], post_dup_hook);

	/* close(2) */
	(void)syscall_set_post(&syscall_desc[__NR_close], post_close_hook);

	/* start execution */
	libdft_start();

	/* typically not reached; make the compiler happy */
	return EXIT_SUCCESS;

err:
	/* error handling */

	/* detach from the process */
	libdft_die();

	/* return */
	return EXIT_FAILURE;
}
