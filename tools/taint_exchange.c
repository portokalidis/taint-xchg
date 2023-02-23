/*-
 * main_dummy.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <set>

#include "libdft_api.h"
#include "syscall_desc.h"
#include "pin.H"

#define SYS_SOCKET      1       /* socket(2) demux index for socketcall */

/* syscall descriptors */
extern syscall_desc_t syscall_desc[SYSCALL_MAX];

/* set of interesting descriptors (sockets) */
static set<int> fdset;

static
void pre_write_hook(syscall_ctx_t *ctx)
{
       // ADDRINT arg2_get=0;
        ADDRINT arg2_set=0;
        //short int vec_elem = 0;
        short int orig_bytes = 0;
        //short int extra_bytes = 0;
        short int new_bytes = 0;
        char *orig_buf = NULL;
        char *new_buf = NULL;
        char *tmp_ptr = NULL;
        char *buf_set = NULL;

        char *abc = "abc";

        printf("SYS_write: arg0:%d\n", ctx->arg[SYSCALL_ARG0]);
        printf("SYS_write: arg1:%s\n", (char*)(ctx->arg[SYSCALL_ARG1]));

        if (fdset.find(ctx->arg[SYSCALL_ARG0]) != fdset.end())
        {
                /*The original args*/
                orig_buf = (char*)(ctx->arg[SYSCALL_ARG1]);
                orig_bytes = (short int)(ctx->arg[SYSCALL_ARG2]);

		//ADDITION to avoid (orig_bytes<0) cases
		//if(orig_bytes >0)
		//{
		printf("PIN_Get(): orig_bytes: %d\n", orig_bytes);

                new_buf = (char *)calloc(orig_bytes+3, sizeof(char));
                memcpy(new_buf, abc, 3);
                printf("pre_write: only abc: %s\n", new_buf);
                tmp_ptr = new_buf + 3;
                new_bytes = orig_bytes + 3;

                memcpy(tmp_ptr, orig_buf, orig_bytes);
                printf("pre_write: tmp_ptr:%s\n", tmp_ptr);
                printf("pre_write: new_buf:%s\n", new_buf);
                PIN_SetSyscallArgument((CONTEXT *)ctx->aux, SYSCALL_STANDARD_IA32_LINUX, 1, (ADDRINT)new_buf);
                PIN_SetSyscallArgument((CONTEXT *)ctx->aux, SYSCALL_STANDARD_IA32_LINUX, 2, new_bytes);
                arg2_set= PIN_GetSyscallArgument((CONTEXT *)ctx->aux, SYSCALL_STANDARD_IA32_LINUX, 2);
                printf("arg2_set = %d\n", (int)arg2_set);
                buf_set = (char*)PIN_GetSyscallArgument((CONTEXT *)ctx->aux, SYSCALL_STANDARD_IA32_LINUX, 1);
		//}
	}
}

static void pre_read_hook(syscall_ctx_t *ctx)
{
        short int arg2_get = 0;
        //short int orig_bytes = 0;
        //short int vec_elem = 0;
        int sfd = 0;
        //short int rem = 0, r = 0;
        char * new_buf;
        //char * tmp_ptr;

        if(fdset.find(ctx->arg[SYSCALL_ARG0]) != fdset.end())
        {
		printf("pre_read_hook()\n");
		sfd = (int)PIN_GetSyscallArgument((CONTEXT *)ctx->aux, SYSCALL_STANDARD_IA32_LINUX, 0);
		printf("pre_read:socket_fd:%d\n", sfd);
		new_buf=(char *)PIN_GetSyscallArgument((CONTEXT *)ctx->aux, SYSCALL_STANDARD_IA32_LINUX, 1);

		arg2_get = (short int)PIN_GetSyscallArgument((CONTEXT *)ctx->aux, SYSCALL_STANDARD_IA32_LINUX, 2);
		printf("pre_read:arg2_get:%d\n", arg2_get);
		PIN_SetSyscallArgument((CONTEXT *)ctx->aux, SYSCALL_STANDARD_IA32_LINUX, 1, (ADDRINT)new_buf-3);
		PIN_SetSyscallArgument((CONTEXT *)ctx->aux, SYSCALL_STANDARD_IA32_LINUX, 2, arg2_get+3);
	}
}

static void post_write_hook(syscall_ctx_t *ctx)
{
	short int rem = 0;
	short int r=0;
	short int sent = 0;
	short int fd;
	char * buf = NULL;

	if (fdset.find(ctx->arg[SYSCALL_ARG0]) != fdset.end())
        {
		sent = PIN_GetSyscallReturn((CONTEXT *)ctx->aux, SYSCALL_STANDARD_IA32_LINUX);
		printf("post_write: sent:%d\n", sent);
		r = (short int)PIN_GetSyscallArgument((CONTEXT *)ctx->aux, SYSCALL_STANDARD_IA32_LINUX, 2);
		rem = r - sent;//(short int)ctx->ret;
        //      if(rem>0)
        //      {
			printf("post_write: rem = %d\n", rem);
			fd = (short int)ctx->arg[SYSCALL_ARG0];
                        //buf = (char*)ctx->arg[SYSCALL_ARG1];
			buf = (char *)PIN_GetSyscallArgument((CONTEXT *)ctx->aux, SYSCALL_STANDARD_IA32_LINUX, 1);
		//}
		printf("post_write:buf:%s\n", buf);
	//	sent = 0;
	//	rem = 0;
	//	r = 0;
	}
}


static void
post_read_hook(syscall_ctx_t *ctx)
{
        char *n_buf;
        char *t_ptr;
        char *buf_set;
	//short int orig_bytes = 0;
	//short int arg2 = 0, r = 0;
        //short int vec_elem =0;
        //short int total_bytes = 0;
        int ret_value = 0;
	int sfd = 0;

        // read() was not successful; optimized branch 
        if (unlikely((long)ctx->ret <= 0))
	{
		printf("post_read:ret:%d\n", (int)ctx->ret);
                return;
	}

        if (fdset.find(ctx->arg[SYSCALL_ARG0]) != fdset.end())
        {
                printf("post_read_hook()\n");
		sfd = (int)PIN_GetSyscallArgument((CONTEXT *)ctx->aux, SYSCALL_STANDARD_IA32_LINUX, 0);
                n_buf = (char *)PIN_GetSyscallArgument((CONTEXT *)ctx->aux, SYSCALL_STANDARD_IA32_LINUX, 1);
                printf("post_read:buf:%s\n", n_buf);


                printf("ctx->ret(read):%d\n", (int)ctx->ret);
                ret_value = (int)ctx->ret;
                PIN_SetContextReg((CONTEXT *)ctx->aux, REG_GR_LAST, (ret_value-3));

                t_ptr = (char*)calloc(10, sizeof(char));
                buf_set = (char*)PIN_GetSyscallArgument((CONTEXT *)ctx->aux, SYSCALL_STANDARD_IA32_LINUX, 1);

                printf("post_read:buf_set:%s\n", buf_set);
                printf("post_read:arg2:%d\n", (int)PIN_GetSyscallArgument((CONTEXT *)ctx->aux, SYSCALL_STANDARD_IA32_LINUX, 2));

                printf("post_read:ctx->ret(set):%d\n", (int)PIN_GetSyscallReturn((CONTEXT *)ctx->aux, SYSCALL_STANDARD_IA32_LINUX));
        }
        else
                printf("read: not tracing!\n");
}

static void
post_socketcall_hook(syscall_ctx_t *ctx)
{
	/*iterator*/
	set<int>::iterator it;

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
                                args[SYSCALL_ARG0] == PF_INET6 ||
                                args[SYSCALL_ARG0] == PF_FILE))
                        {
                                /* add the descriptor to the monitored set */
                                fdset.insert((int)ctx->ret);
                                printf("SOCKET:ret: %d\n", (int)ctx->ret);
                                //for(it=fdset.begin(); it!=fdset.end(); it++)
                                //{

                                //}
                        }

                        /* done */
                        break;
                case SYS_ACCEPT:
                        printf("Caught SYS_ACCEPT!\n");
                        printf("ACCEPT:ret: %d\n", (int)ctx->ret);
                        if(likely(fdset.find(args[SYSCALL_ARG0])!= fdset.end()))
                        {
                                fdset.insert((int)ctx->ret);
                                printf("ACCEPT:ret: %d\n", (int)ctx->ret);
                        }
                        break;
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
                                break;

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
        set<int>::iterator it2;

        /* not successful; optimized branch */
        if (unlikely((long)ctx->ret < 0))
                return;
        printf("post_close(%d)\n", (int)ctx->arg[SYSCALL_ARG0]);
//      printf("post_close: BEFORE ERASE!\n");
        for(it2 = fdset.begin();it2!=fdset.end(); ++it2)
        {
                printf("In fdset: %d\n", *it2);
        }
        /*
         * if the descriptor (argument) is
         * interesting, remove it from the
         * monitored set
         */
        it = fdset.find((int)ctx->arg[SYSCALL_ARG0]);
        //it = fdset_write.find((int)ctx->arg[SYSCALL_ARG0]);
        if (likely(it != fdset.end()))
        {
                printf("close(SYSCALL_ARG0): %d", (int)ctx->arg[SYSCALL_ARG0]);
                fdset.erase(it);
                printf("post_close: AFTER ERASE!\n");
                for(it2 = fdset.begin();it2!=fdset.end(); ++it2)
                printf("In fdset: %d\n", *it2);

        }
}
int
main(int argc, char **argv)
{
        /* initialize the core tagging engine */
        if (libdft_init(argc, argv))
                /* failed */
                goto err;


        syscall_set_pre(&syscall_desc[__NR_write], pre_write_hook);
        syscall_set_pre(&syscall_desc[__NR_read], pre_read_hook);
        syscall_set_post(&syscall_desc[__NR_write], post_write_hook);
        syscall_set_post(&syscall_desc[__NR_read], post_read_hook);
        syscall_set_post(&syscall_desc[__NR_socketcall], post_socketcall_hook);
        syscall_set_post(&syscall_desc[__NR_dup], post_dup_hook);
        syscall_set_post(&syscall_desc[__NR_close], post_close_hook);

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

