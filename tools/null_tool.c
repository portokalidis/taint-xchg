#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>

#include "pin.H"
#include "branch_pred.h"



VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	PIN_GetContextReg(ctxt, REG_INST_PTR);
	PIN_GetSyscallNumber(ctxt, std);
	PIN_GetSyscallArgument(ctxt, std, 0);
	PIN_GetSyscallArgument(ctxt, std, 1);
	PIN_GetSyscallArgument(ctxt, std, 2);
	PIN_GetSyscallArgument(ctxt, std, 3);
	PIN_GetSyscallArgument(ctxt, std, 4);
	PIN_GetSyscallArgument(ctxt, std, 5);
}

VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	PIN_GetSyscallReturn(ctxt, std);
}

/*INT32 Usage()
{
	PIN_ERROR("This tool prints a log of system call numbers"
			+ KNOB_BASE::StringKnobSummary() + "\n");
	return -1;
}*/

/*
 * null_tool
 *
 * used for estimating the overhead of Pin
 * includes only callbacks for system calls
 */
int
main(int argc, char **argv)
{
	/* initialize symbol processing */
	PIN_InitSymbols();
	
	/* initialize PIN; optimized branch */
	if (unlikely(PIN_Init(argc, argv)))
		/* PIN initialization failed */
		goto err;
	
	/* Callbacks for system calls*/
	PIN_AddSyscallEntryFunction(SyscallEntry, 0);
	PIN_AddSyscallExitFunction(SyscallExit, 0);

	/* start PIN */
	PIN_StartProgram();

	/* typically not reached; make the compiler happy */
	return EXIT_SUCCESS;

err:
	/* error handling */

	/* return */
	return EXIT_FAILURE;
}
