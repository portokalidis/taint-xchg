/*-
 * taint_xchg.c
 */

extern "C" {
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <sys/mman.h>
}

#include <cassert>
#include <set>

#include "libdft_api.h"
#include "syscall_desc.h"
#include "tagmap.h"
#include "pin.H"

#define BYTE_MASK       0x01U           /* byte mask; 1 bit */

/* the default taint configuration file */
#define CONFIG_DFL	"taint_config.txt"

#define SYS_SOCKET      1       /* socket(2) demux index for socketcall */

/* given a virtual address estimate the byte offset on the bitmap */
#define VIRT2BYTE(addr) ((addr) >> 3)

/* given a virtual address estimate the bit offset on the bitmap */
#define VIRT2BIT(addr)  ((addr) & 0x00000007U)
#define CEIL(x,y)	(((x) + ((y)-1)) / (y))

//#define debug_write(fmt, ...)	printf(fmt, __VA_ARGS__)

//#define debug_write(fmt, ...)	do{ }while(0);

#ifdef DEBUG_ENABLE
#define DEBUG(...) \
	do{	printf("%s: ", __func__); 	\
		printf(__VA_ARGS__);		\
		puts("");			\
	}while(0)
#else
#define DEBUG(...) do { } while(0)
#endif


/* syscall descriptors */
extern syscall_desc_t syscall_desc[SYSCALL_MAX];

/* set of tainted files in the taint_conf file */
static set<string> confset;

/* ********************************************************************** */
/* Commandline Switches							  */ 
/* ********************************************************************** */
//KNOB<BOOL> set_dft(KNOB_MODE_WRITEONCE, "pintool", "on", o, "dft on");

//KNOB<BOOL> unset_dft(KNOB_MODE_WRITEONCE, "pintool", "off", o, "dft off");

KNOB<string> taint_conf(KNOB_MODE_WRITEONCE, "pintool", "i", CONFIG_DFL, "");

/*
 * Bitmap will hold the taint information for the bytes 
 * in the buffer of a write() system call. 
 * The size of the bitmap will be 1/8 of the size 
 * of the buffer to be written to the socket.
 * Use one bitmap per write(), which will be created 
 * in pre_write_hook() and free-ed in post_write_hook().
 */
struct taint_hdr{
	long l_hdr;
	long l_data;
	unsigned char taint_type;
	unsigned char bitmap[1];
} __attribute((__packed__));


struct state_read {
	short int data_or_hdr;		/* 1 if buffer read includes header, 
					   0 if buffer includes only data */
	long l_tmp_ptr;			/* the size of tmp_ptr*/
	long l_data;			/* size of raw data, set in pre_write() and pre_send(),
					   updated in post_read() and post_recv() */
	short int fd_type;		/* the type of the fd, 1 for socket_desc, 0 for file_desc*/	
	unsigned char *tmp_ptr;		/* the taint_hdr */
};

struct state_read *state_sfd[100]={NULL};

/*
 * initialize the relevant entry in the state_sfd[]
 *
 * input:	socket descriptor
 * returns:	0 on success,
 * 		1 on failure
 *
 */

int state_init(int sfd, short int fd_type)
{
	/* initialize the state_sfd[sfd] entry */
	if(unlikely((state_sfd[sfd] = (struct state_read *)calloc(sizeof(struct state_read), 1)) == NULL))
		/* allocation failed, return with failure */
		return 1;

	state_sfd[sfd]->data_or_hdr = 1;
	state_sfd[sfd]->l_tmp_ptr = sizeof(struct taint_hdr);
	if(unlikely((state_sfd[sfd]->tmp_ptr = (unsigned char *)calloc(sizeof(struct taint_hdr),1)) == NULL))
		/* allocation failed, return with failure */
		return 1;

	DEBUG(":added sfd:%d to state_sfd\n", sfd);
	state_sfd[sfd]->l_data = 0;
	state_sfd[sfd]->fd_type = fd_type;
	/* success */
	return 0;
}
#if 0
int
bitmap_alloc(int size)
{
	/*
	 * allocate space for the bitmap;
	 * size: size in bits of the bitarray to be initialized
	 * (equals the size of the buffer to be sent
	 *
	 */

	/* allocation must be positive*/
	if(size <= 0)
	{
		/* return with failure */
		return 1;
	}
	if(unlikely((_bitmap = (uint8_t *)calloc(CEIL(size,8), 1))==NULL))
	{
		/* return with failure */
		return 1;
	}
	/* return with success */
	return 0;
}

void
bitmap_free(void)
{
	/* deallocate the bitmap */
	free(_bitmap);
}
/*
 *  untag a byte on the virtual address space
 *  @addr:       the virtual address
 *
 */


static void 
bitmap_clrb(char *bmap, size_t addr)
{
	/* clear the bit that corresponds to the given address */
	bmap[VIRT2BYTE(addr)] &= ~(BYTE_MASK << VIRT2BIT(addr));
}
#endif

/*
 * tag a byte on the bitmap @addr:
 * the virtual address
 *
 */

static void 
bitmap_setb(unsigned char *bmap, size_t addr)
{
	/* assert the bit that corresponds to the given address */
	bmap[VIRT2BYTE(addr)] |= (BYTE_MASK << VIRT2BIT(addr));
}


/*
 *  get the tag value of a byte from the tagmap
 *  @addr:       the virtual address
 *  returns:     the tag value (e.g., 0, 1,...)
 *  
 */

size_t
bitmap_getb(unsigned char *bmap, size_t addr)
{
	/* get the bit that corresponds to the address */
	return bmap[VIRT2BYTE(addr)] & (BYTE_MASK << VIRT2BIT(addr));
}

int
rand_gen(int size)
{
	int position = 0;

	if(size <= 0)
		return -1;

	position = rand() % size;
	return position;
}

static
void pre_write_hook(syscall_ctx_t *ctx)
{
        //short int vec_elem = 0;
	short int r = 0;
	short int i=0;
	int counter = 0;
	long l_hdr = 0;	/* length of header */
	long l_data = 0;	/* length of actual data*/
	short int l_bmap = 0;	/* length of bitmap */
        char *orig_buf = NULL;
	struct taint_hdr *hdr = NULL;

	if((state_sfd[ctx->arg[SYSCALL_ARG0]] != NULL))
	{
                /*The original args*/
                orig_buf = (char*)(ctx->arg[SYSCALL_ARG1]);
                l_data = (long)(ctx->arg[SYSCALL_ARG2]); // XXX: Possible loss of data
		DEBUG("l_data:%ld\n", l_data);
		
		//avoid (l_data<0) cases
		if(l_data >0)
		{
			l_bmap = CEIL(l_data, 8);
			// The length of the struct + the length of the bitmap
			// -1 because the struct already includes 1 byte for the
			// bitmap
			l_hdr = sizeof(struct taint_hdr) + l_bmap - 1;
			DEBUG("sizeof(struct taint_hdr):%d\n", sizeof(struct taint_hdr));
			DEBUG("l_bmap=CEIL(orig_bytes,8):%d\n", l_bmap);
			DEBUG("l_hdr = %ld\n", l_hdr);
			hdr = (struct taint_hdr *)calloc(l_hdr, 1);
			assert(hdr);
			hdr->l_hdr = l_hdr;
			hdr->l_data = l_data;
			for(i = 0; i<l_data; i++)
			{
				if(tagmap_getb((size_t)(orig_buf+i))!=0)
				{
					/*if(isprint(orig_buf[i])!=0)
					{
						DEBUG("i=%d, %c", i, orig_buf[i]);
					}
					else
					{
						DEBUG("i=%d, \\%o", i, orig_buf[i]);
					}*/
					bitmap_setb(hdr->bitmap, i);
					counter++;
				}
			}
			DEBUG("tainted_bytes in buf:%d", counter);
			/*for (i = 0; i < 10; i++) {
				position = rand_gen(l_data);
				// XXX: You can get real taint with something
				// like this
				// taint_map_getb(orig_buf + position)
				bitmap_setb(hdr->bitmap, position);
			}*/
			if((r = write(ctx->arg[SYSCALL_ARG0], hdr, l_hdr))>0)
			{
				DEBUG("Sending %d bytes of taint_header!", r);
				DEBUG("hdr->l_hdr:%ld, hdr->l_data:%ld", hdr->l_hdr, hdr->l_data);
			} // XXX: Check for error
			free(hdr);
			hdr = NULL;
		}
	  }
}

/*Note: arg1 contents are not available in pre_read, only the memory address where they are going to be stored*/
static void pre_read_hook(syscall_ctx_t *ctx)
{
        long data_max = 0;
        //short int vec_elem = 0;
	short int r=0, r1= 0;
        int sfd = 0;
        //char * new_buf;
	struct taint_hdr *hdr;

	/* 1 way*/
	//hdr->l_hdr;
	
	/* 2nd way */
	//((struct taint_hdr *)tmp_ptr)->l_hdr;

	if((state_sfd[(int)ctx->arg[SYSCALL_ARG0]]!=NULL))
	{
		if(state_sfd[(int)ctx->arg[SYSCALL_ARG0]]->data_or_hdr == 1)
		{
			sfd = (int)ctx->arg[SYSCALL_ARG0];
			//printf("pre_read:socket_fd:%d\n", sfd);
			DEBUG("socket_fd:%d", sfd);
			hdr = (struct taint_hdr *)state_sfd[sfd]->tmp_ptr;
			assert(hdr);
			//new_buf=(char *)PIN_GetSyscallArgument((CONTEXT *)ctx->aux, SYSCALL_STANDARD_IA32_LINUX, 1);

			data_max = (long)ctx->arg[SYSCALL_ARG2];
			DEBUG("pre_read:data_max:%ld", data_max);

			if((r=read(sfd, state_sfd[sfd]->tmp_ptr, 2*sizeof(long)))== 2*sizeof(long))
			{
				/* extract the l_hdr */
				DEBUG(" l_hdr: %ld", hdr->l_hdr);
				/* extract the l_data */
				DEBUG(" l_data: %ld", hdr->l_data);
				state_sfd[sfd]->l_data = hdr->l_data;
				DEBUG("Received %d bytes of header...", r);

				/* Could use the bitmap_alloc(l_data) function */

				if(state_sfd[sfd]->l_tmp_ptr < hdr->l_hdr)
				{
					state_sfd[sfd]->tmp_ptr =(unsigned char *)realloc(state_sfd[sfd]->tmp_ptr, hdr->l_hdr);
					assert(state_sfd[sfd]->tmp_ptr);
					hdr = (struct taint_hdr *)state_sfd[sfd]->tmp_ptr;
					state_sfd[sfd]->l_tmp_ptr = hdr->l_hdr;
					DEBUG("hdr->l_hdr:%ld", hdr->l_hdr);
				}
				if((r1 = read(sfd, (unsigned char *)hdr->bitmap, hdr->l_hdr-(sizeof(hdr->l_hdr)+sizeof(hdr->l_data))))>0)
				{
					DEBUG("Received %d bytes of bitmap_read", r1);
					state_sfd[sfd]->data_or_hdr = 0;
        			}
				else
				{
					DEBUG(" Only %d bytes of bitmap_read received", r1);
					state_sfd[sfd]->data_or_hdr = 1; 
					//value 3 implies that part of bitmap is not yet received
				}
			}
			else
			{
				DEBUG(" Iniial hdr reading failed. Only %d bytes of l_hdr received", r);
				/* Have to add more for partial receiving of hdr */
				state_sfd[sfd]->data_or_hdr = 1;
				//value 2 implies that part of bitmap is not yet received
			}

			hdr = NULL;
		}
		/* if (data_or_hdr != 1) */
		else
			DEBUG(" Receiving only data...");
	}
}

/*
 * socketcall(2) handler
 *
 * attach taint-sources in the following
 * syscalls:
 * 	socket(2), accept(2), accept(4),
 *
 * attach taint-info in the following
 * syscalls:
 * 	send(2)
 *
 * extract taint-info in the following
 * syscalls:
 * 	send(2)
 *
 */

static void 
pre_socketcall_hook(syscall_ctx_t *ctx)
{
        /* socket call arguments */
        unsigned long *args = (unsigned long *)ctx->arg[SYSCALL_ARG1];

	/* local variables */
	struct taint_hdr *hdr_r;
	struct taint_hdr *hdr_s;
	char *orig_buf = NULL;
	int sfd;
	int r, r1, i, counter=0;
	short int l_bmap=0;
	long l_data=0, l_hdr=0;

        /* demultiplex the socketcall */
        switch ((int)ctx->arg[SYSCALL_ARG0]) {
		
		case SYS_RECV:
			DEBUG("pre_recv: before if: sfd: %d", (int)args[SYSCALL_ARG0]);
                        /* not successful; optimized branch */
                        if (unlikely((long)ctx->ret <= 0))
                                return;

			/*
			 * if the socket fd is interesting,
			 * the data received should me monitored
			 */

			if(state_sfd[args[SYSCALL_ARG0]] != NULL)
			{
				DEBUG("pre_recv: sfd: %d", (int)args[SYSCALL_ARG0]);
				if(state_sfd[args[SYSCALL_ARG0]]->data_or_hdr == 1)
				{
					sfd = (int)args[SYSCALL_ARG0];
					hdr_r = (struct taint_hdr *)state_sfd[sfd]->tmp_ptr; 
					assert(hdr_r);
					/* Read hdr-size and data-size */ 
					if((r=read(sfd, state_sfd[sfd]->tmp_ptr, sizeof(l_data)+sizeof(l_hdr))) == 2*sizeof(long))
					{
						/* extract l_hdr */
						DEBUG("pre_recv: %ld",hdr_r->l_hdr);
						/* extract l_data */
						state_sfd[sfd]->l_data = hdr_r->l_data;
						
						if(state_sfd[sfd]->l_tmp_ptr < hdr_r->l_hdr)
						{
							state_sfd[sfd]->tmp_ptr =(unsigned char *)realloc(state_sfd[sfd]->tmp_ptr, hdr_r->l_hdr);
							assert(state_sfd[sfd]->tmp_ptr);
							hdr_r = (struct taint_hdr *)state_sfd[sfd]->tmp_ptr;
							state_sfd[sfd]->l_tmp_ptr = hdr_r->l_hdr;
							DEBUG("pre_recv:hdr->l_hdr:%ld", hdr_r->l_hdr);
						}
						if((r1 = read(sfd, (unsigned char *)hdr_r->bitmap, hdr_r->l_hdr-(sizeof(hdr_r->l_hdr)+sizeof(hdr_r->l_data))))>0)
						{
							DEBUG("pre_recv: Received %d bytes of bitmap_recv", r1);
							state_sfd[sfd]->data_or_hdr = 0;
        					}
						else
						{
							DEBUG("pre_recv: Only %d bytes of bitmap_read received", r1);
							state_sfd[sfd]->data_or_hdr = 1; 
							//value 3 implies that part of bitmap is not yet received
						}
					}
					else
					{
						DEBUG("pre_recv: Iniial hdr reading failed. Only %d bytes of l_hdr received", r);
						/* Have to add more for partial receiving of hdr */
						state_sfd[sfd]->data_or_hdr = 1;
						//value 2 implies that part of bitmap is not yet received
					}
	
					hdr_r = NULL;
				}
				/* if (data_or_hdr != 1) */
				else
					DEBUG("pre_recv: Receiving only data...");
			}
			break;
		case SYS_SEND:

                        /* not successful; optimized branch */
                        if (unlikely((long)ctx->ret <= 0))
                                return;

			/*
			 * if the socket fd is interesting,
			 * the data sent should me added
			 * a taint-hdr
			 */
			
			if(state_sfd[args[SYSCALL_ARG0]] != NULL)
			{
				l_data=args[SYSCALL_ARG2];
				orig_buf = (char*)args[SYSCALL_ARG1];
				//avoid (l_data<0) cases
				if(l_data >0)
				{
					l_bmap = CEIL(l_data, 8);
					DEBUG("pre_send: sizeof(struct taint_hdr): %d\n", sizeof(struct taint_hdr));
					// The length of the struct + the length of the bitmap
					// -1 because the struct already includes 1 byte for 
					// the bitmap
					l_hdr = sizeof(struct taint_hdr) + l_bmap - 1;
					DEBUG("pre_send:l_bmap=CEIL(orig_bytes,8):%d", l_bmap);
					DEBUG("pre_send:l_hdr = %ld", l_hdr);
					hdr_s = (struct taint_hdr *)calloc(l_hdr, 1);
					assert(hdr_s);
					hdr_s->l_hdr = l_hdr;
					hdr_s->l_data = l_data;
					DEBUG("pre_send:print only the tainted bytes.");
					for(i = 0; i<l_data; i++)
					{
						if(tagmap_getb((size_t)(orig_buf+i))!=0)
						{
							/*if(isprint(orig_buf[i])!=0)
							{
								DEBUG("i=%d, %c", i, orig_buf[i]);
							}
							else
							{
								DEBUG("i=%d, \\%o", i, orig_buf[i]);
							}*/
							bitmap_setb(hdr_s->bitmap, i);
							counter++;
						}
					}	
					DEBUG(" tainted_bytes in buf:%d", counter);
					/*for (i = 0; i < 10; i++) {
					position = rand_gen(l_data);
					// XXX: You can get real taint with something
					// like this
					// taint_map_getb(orig_buf + position)
					bitmap_setb(hdr->bitmap, position);
					}*/	
					if((r = write(args[SYSCALL_ARG0], hdr_s, l_hdr))>0)
					{
						DEBUG("pre_send: Sending %d bytes of taint_header!", r);
						DEBUG("pre_send: hdr->l_hdr:%ld, hdr->l_data:%ld", hdr_s->l_hdr, hdr_s->l_data);
					} // XXX: Check for error
					free(hdr_s);
					hdr_s = NULL;
				}
			}
			
			break;
		default:
			/* nothing to do*/
			return;
	}
}

static void post_unhandle_hook(syscall_ctx_t *ctx)
{
	if((state_sfd[ctx->arg[SYSCALL_ARG0]] != NULL))
	{
		DEBUG(" on tainted fd");
	}

	if(unlikely((long)ctx->ret) <=0)
	{
		DEBUG("ret:%ld", (long)ctx->ret);
	}
}

static void post_write_hook(syscall_ctx_t *ctx)
{
	short int rem = 0;
	short int r=0;
	short int sent = 0;

	if(unlikely((long)ctx->ret <= 0))
		return;

	if((state_sfd[ctx->arg[SYSCALL_ARG0]] != NULL))
	{
        
		sent = (int)ctx->ret;
		DEBUG(" sent:%d", sent);
		r = (short int)ctx->arg[SYSCALL_ARG2];
		rem = r - sent;
        	DEBUG("rem = %d", rem);
		if(rem>0)
		{
			DEBUG("Not all data written to socket.");
		}
		sent = 0;
		rem = 0;
		r = 0;
	}
}


static void
post_read_hook(syscall_ctx_t *ctx)
{
        char *n_buf;
        int ret_value = 0;
	int sfd = 0;
	int i=0;
	int count=0;
	struct taint_hdr *hdr = NULL;

        // read() was not successful; optimized branch 
        if (unlikely((long)ctx->ret <= 0))
	{
		DEBUG("fail:ret:%d", (int)ctx->ret);
                return;
	}
	
	if(state_sfd[ctx->arg[SYSCALL_ARG0]] != NULL)
	{
		sfd = (int)ctx->arg[SYSCALL_ARG0];
		n_buf = (char *)ctx->arg[SYSCALL_ARG1];
		hdr=(struct taint_hdr *)state_sfd[sfd]->tmp_ptr;
		assert(hdr);
		DEBUG(" hdr->l_hdr:%ld", hdr->l_hdr);
		DEBUG(" hdr->l_data:%ld", hdr->l_data);
		DEBUG(" state_sfd[sfd]->fd_type:%d", state_sfd[sfd]->fd_type);
                DEBUG("ctx->ret:%ld", (long)ctx->ret);
                ret_value = (int)ctx->ret;


		if(state_sfd[sfd]->fd_type == 0) 
		{
			tagmap_setn((size_t)n_buf, ret_value);
			DEBUG(" Tainted %d bytes", ret_value);
		}
		/*
		 *The following 2 checks succeed only for data read from sockets
		 */

		/* this will never succeed for data read from a tainted file, 
		 * since there the l_data value is set by state_init to 0 
		 * (by calloc'ing state_sfd[sfd]tmp_ptr) */
		
		/* update the state for next read() */
		if(ret_value == (int)(state_sfd[sfd]->l_data))
		{
			DEBUG("Received all expected data...");
			/* Extract the bitmap and tag the relevant bytes in the buffer */

			
			/* reading from a socket */
			if(state_sfd[sfd]->fd_type == 1)
			{	
				for(i=0; i<ret_value; i++)
				{
					/*if tainted*/
					if((bitmap_getb((hdr->bitmap), i))!=0)
					{
						count++;
						/*if(isprint(n_buf[i])!=0)
						{
							DEBUG("bitmap[%d]: %c ", i, n_buf[i]);
						}
						else
							DEBUG("bitmap[%d]: \\%o ",i, n_buf[i]);
						*/
						tagmap_setb((size_t)(ctx->arg[SYSCALL_ARG1]+i));
					}
					else
						tagmap_clrb((size_t)(ctx->arg[SYSCALL_ARG1]+i));
				}
				DEBUG(" Found %d bytes tainted in buf_read\n", count);

				state_sfd[sfd]->data_or_hdr = 1;
				DEBUG("state_sfd[%d]->data_or_hdr = %d", sfd, state_sfd[sfd]->data_or_hdr);
	//		state_sfd[sfd]->l_data = 0;
			}
			//printf("memset:(state_sfd[%d]->l_tmp_ptr):%d\n", sfd, state_sfd[sfd]->l_tmp_ptr);
			/* Initialize the state_read[sfd]->tmp_ptr */
			memset(state_sfd[sfd]->tmp_ptr, 0, state_sfd[sfd]->l_tmp_ptr);
		}
                if(ret_value < (int)(state_sfd[sfd]->l_data))
		{
			state_sfd[sfd]->data_or_hdr = 0;
			state_sfd[sfd]->l_data -= ret_value;
			DEBUG(" updated state_sfd[%d]->l_data: %ld", sfd, state_sfd[sfd]->l_data);
		}
		/*for(i=0; i<ret_value; i++)
		{
			if(isprint(n_buf[i])!=0)
			{
				DEBUG("%c", n_buf[i]);
			}
			else
				DEBUG("\\%o", n_buf[i]);
		}*/

	}
	else
		/* clear tag bits*/
		tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
}

static void
post_open_hook(syscall_ctx_t *ctx)
{
	set<string>:: iterator it;
	char path[PATH_MAX];
	char f_name[20]={0};
	pid_t pid;
	char pid_s[20]={0};
	char fd_s[3]={0};
	ssize_t count, count1;

	/* not successful; optimized branch */
	if(unlikely((long)ctx->ret) < 0)
		return;

	memset(path, 0, PATH_MAX);
	pid=getpid();
	strcpy(f_name, "/proc/");
	sprintf(pid_s, "%d", pid);
	strcat(f_name, pid_s);
	strcat(f_name, "/fd/");
	sprintf(fd_s, "%d", (int)ctx->ret);
	strcat(f_name, fd_s);
	DEBUG("SYSCALL_ARGO:%s", (char *)ctx->arg[SYSCALL_ARG0]);
	//count = readlink("/proc/self/exe", path, PATH_MAX);
	//DEBUG("f_name:%s\n", f_name);
	count1 = readlink(f_name, path, PATH_MAX);
	DEBUG("readlink_on_arg0: %s", path);
	
	/*for(i=0; i<count1+1; i++)
	{
		if(isprint(path[i])!=0)
		{
			DEBUG("%c ", path[i]);
		}
		else
			DEBUG("\\%o ", path[i]);
	}*/
	if(confset.find(path) != confset.end())
	{
		DEBUG(" Found file");
		/* add the descriptor to the monitored state_sfd */
		if(state_sfd[(int)ctx->ret] == NULL)
		{
			if(unlikely(state_init((int)ctx->ret, 0)))
				return;

			DEBUG(" path: %s, added (ctx->ret):%d", (char *)ctx->arg[SYSCALL_ARG0], (int)ctx->ret);
			state_sfd[(int)ctx->ret]->data_or_hdr = 0;
		}

	}
		
}

static void
post_mmap_hook(syscall_ctx_t *ctx)
{
	/* the map offset */
	size_t offset = (size_t)ctx->arg[SYSCALL_ARG1];

	if(unlikely((void *)ctx->ret == MAP_FAILED))
		return;

	/* estimate offset; optimized branch */
	if (unlikely(offset < PAGE_SZ))
		offset = PAGE_SZ;
	else
		offset = offset + PAGE_SZ - (offset % PAGE_SZ);

	/* grow downwards; optimized branch */
	if (unlikely((int)ctx->arg[SYSCALL_ARG3] & MAP_GROWSDOWN))
		/* fix starting address */
		ctx->ret = ctx->ret + offset - 1;
	
	/* 
	 * clear tag bits for anonymous mmap and for non-interesting fds, 
	 * taint mapped area for monitored fds 
	 * */

	if(((int)ctx->arg[SYSCALL_ARG4] < 0) || (state_sfd[(int)ctx->arg[SYSCALL_ARG4]] == NULL))
		/* emulate the clear_tag() call */
		tagmap_clrn((size_t)ctx->ret, offset);
	else
		tagmap_setn((size_t)ctx->ret, offset);
	
}

static void
post_socketcall_hook(syscall_ctx_t *ctx)
{
        /* socket call arguments */
        unsigned long *args = (unsigned long *)ctx->arg[SYSCALL_ARG1];

	/* local variables */
	struct taint_hdr *hdr;
	char *n_buf = NULL;
	int ret_value = 0;
	int rem = 0, i=0;
	int sfd;

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
                                args[SYSCALL_ARG0] == PF_INET6)) //||
                                //args[SYSCALL_ARG0] == PF_FILE))
                        {
                                /* add the descriptor to the monitored state_sfd */
				if(state_sfd[(int)ctx->ret] == NULL)
				{
					if(unlikely(state_init((int)ctx->ret, 1)))
						return;
				}

                                DEBUG("post_socket:ret: %d", (int)ctx->ret);
                        }

                        /* done */
                        break;
                case SYS_ACCEPT:
			/* not successful; optimized branch*/
			if (unlikely((long)ctx->ret < 0))
				return;

			DEBUG("post_accept: ret: %d", (int)ctx->ret);
			/* if the socket argument is interesting,
			 * the returned handle of accept() is also
			 * interesting
			 */
			if((state_sfd[args[SYSCALL_ARG0]] != NULL) && (state_sfd[ctx->ret] == NULL))
			{
				if(unlikely(state_init((int)ctx->ret, 1)))
					return;
			}
			/* addr argument is provided */
			if ((void *)args[SYSCALL_ARG1] != NULL) {
				/* clear the tag bits */
				tagmap_clrn(args[SYSCALL_ARG1],
					*((int *)args[SYSCALL_ARG2]));
				
				/* clear the tag bits */
				tagmap_clrn(args[SYSCALL_ARG2], sizeof(int));
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
                        
			/* add the descriptor to the monitored set */
			if((state_sfd[args[SYSCALL_ARG0]] != NULL) && (state_sfd[ctx->ret] == NULL))
			{
				if(unlikely(state_init((int)ctx->ret, 1)))
					return;

			}
			/* addr argument is provided */
			if ((void *)args[SYSCALL_ARG1] != NULL) {
				/* clear the tag bits */
				tagmap_clrn(args[SYSCALL_ARG1],
					*((int *)args[SYSCALL_ARG2]));
				
				/* clear the tag bits */
				tagmap_clrn(args[SYSCALL_ARG2], sizeof(int));
			}
			break;
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
		case SYS_SEND:
			/* not successful; optimized branch */
			if (unlikely((long)ctx->ret < 0))
				return;
	
			if(state_sfd[args[SYSCALL_ARG0]] != NULL)
			{
				rem = (int)args[SYSCALL_ARG2] - (int)ctx->ret;
				if(rem>0)
				{
					DEBUG("post_send:ALERT:Not all data sent.. Remaining %d bytes", rem);
				}
			}
			break;

		case SYS_RECV:
                        /* not successful; optimized branch */
                        if (unlikely((long)ctx->ret <= 0))
                                return;

			/*
			 * if the socket fd is interesting,
			 * the data received should me monitored
			 */

			if(state_sfd[args[SYSCALL_ARG0]] != NULL)
			{
				if(state_sfd[args[SYSCALL_ARG0]]->data_or_hdr == 1);
				{
					sfd = (int)args[SYSCALL_ARG0];
					n_buf = (char *)args[SYSCALL_ARG1];
					hdr=(struct taint_hdr *)state_sfd[sfd]->tmp_ptr;
					assert(hdr);
					DEBUG("post_recv: hdr->l_hdr:%ld", hdr->l_hdr);
					DEBUG("post_recv: hdr->l_data:%ld", hdr->l_data);
					DEBUG("post_recv: state_sfd[sfd]->fd_type:%d", state_sfd[sfd]->fd_type);
                			DEBUG("post_recv: ctx->ret:%d", (int)ctx->ret);
                			ret_value = (int)ctx->ret;
				}
				
				/* update the state for next recv()*/
				if(ret_value == (int)state_sfd[sfd]->l_data)
				{
					DEBUG(" Received all expected data...");
					/* Extract the bitmap and tag the relevant bytes in the buffer */

					/* reading from a socket */
					if(state_sfd[sfd]->fd_type == 1)
					{	
						DEBUG("post_recv: Print only the tainted bytes.");
						for(i=0; i<ret_value; i++)
						{
							/*if tainted*/
							if((bitmap_getb((hdr->bitmap), i))!=0)
							{
								/*if(isprint(n_buf[i])!=0)
								{
									DEBUG("bitmap[%d]: %c", i, n_buf[i]);
								}	
								else
									DEBUG("bitmap[%d]: \\%o",i, n_buf[i]);*/
								/*taint bytes according to bitmap*/
								tagmap_setb((size_t)(args[SYSCALL_ARG1]+i));
							}	
							else
								tagmap_clrb((size_t)(args[SYSCALL_ARG1]+i));
						}

						state_sfd[sfd]->data_or_hdr = 1;
						DEBUG("post_recv: state_sfd[%d]->data_or_hdr = %d", sfd, state_sfd[sfd]->data_or_hdr);
						/* Initialize the state_read[sfd]->tmp_ptr */
						memset(state_sfd[sfd]->tmp_ptr, 0, state_sfd[sfd]->l_tmp_ptr);
				//		state_sfd[sfd]->l_data = 0;
					}
				}
                		if(ret_value < (int)(state_sfd[sfd]->l_data))
				{
					state_sfd[sfd]->data_or_hdr = 0;
					state_sfd[sfd]->l_data -= ret_value;
					DEBUG("post_recv: updated state_sfd[%d]->l_data: %ld", sfd, state_sfd[sfd]->l_data);
				}
				/*for(i=0; i<ret_value; i++)
				{
					if(isprint(n_buf[i])!=0)
					{
						DEBUG("%c", n_buf[i]);
					}
					else
						DEBUG("\\%o", n_buf[i]);
				}*/
			}
			else
				/* clear tag bits*/
				tagmap_clrn(args[SYSCALL_ARG1], (size_t)ctx->ret);
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
	if((state_sfd[(int)ctx->arg[SYSCALL_ARG0]] != NULL) && (state_sfd[ctx->ret] == NULL))
	{
		if(unlikely(state_init((int)ctx->ret, 1)))
		{
			DEBUG(" failure in state_init(%d, 1)", (int)ctx->ret);
			return;
		}
	}

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

        /* not successful; optimized branch */
        if (unlikely((long)ctx->ret < 0))
                return;
        DEBUG("(%d)", (int)ctx->arg[SYSCALL_ARG0]);
        /*
         * if the descriptor (argument) is
         * interesting, remove it from the
         * monitored set
         */
	if(state_sfd[ctx->arg[SYSCALL_ARG0]] != NULL)
	{
		//free(state_sfd[ctx->arg[SYSCALL_ARG0]]);
		state_sfd[ctx->arg[SYSCALL_ARG0]] = NULL;
	}
}

int
main(int argc, char **argv)
{

	/* Configuration file for the files considered tainted */
	FILE * taint_file;
	char line[256];
	int i =0;

	set<string>::iterator it;

        /* initialize the core tagging engine */
        if (libdft_init(argc, argv))
                /* failed */
                goto err;
	
//	srand(time(NULL));

	if(likely((taint_file = fopen(taint_conf.Value().c_str(), "r")) !=  NULL))
	{
		for(i=0; i<256; i++)
			line[i]='\0';
//		printf("The configuration file is %s \n", taint_conf.Value().c_str());
		/* read contents of taint-file and
		 * add them to the set of tainted files
		 * for monitoring */
		while(fgets(line, sizeof(line), taint_file) != NULL)
		{
			if(line[strlen(line)-1] == '\n')
				line[strlen(line)-1] = '\0';
		//	if(confset.find(line)!= confset.end())
		//	{
		//		printf("main:Added file %s to confset\n", line);
				confset.insert(line);
		//	}
		}
	
	}
	else
		/* failed */
		DEBUG("%s: failed to open", taint_conf.Value().c_str());

	syscall_set_pre(&syscall_desc[__NR_write], pre_write_hook);
	syscall_set_pre(&syscall_desc[__NR_read], pre_read_hook);
	syscall_set_pre(&syscall_desc[__NR_pread64], pre_read_hook);
	syscall_set_pre(&syscall_desc[__NR_socketcall], pre_socketcall_hook);
	syscall_set_post(&syscall_desc[__NR_readv], post_unhandle_hook);
	syscall_set_post(&syscall_desc[__NR_writev], post_unhandle_hook);
	syscall_set_post(&syscall_desc[__NR_pread64], post_read_hook);
	syscall_set_post(&syscall_desc[__NR_pwrite64], post_unhandle_hook);
	syscall_set_post(&syscall_desc[__NR_write], post_write_hook);
	syscall_set_post(&syscall_desc[__NR_read], post_read_hook);
	syscall_set_post(&syscall_desc[__NR_open], post_open_hook);
	syscall_set_post(&syscall_desc[__NR_mmap], post_mmap_hook);
	syscall_set_post(&syscall_desc[__NR_socketcall], post_socketcall_hook);
	syscall_set_post(&syscall_desc[__NR_dup], post_dup_hook);
	syscall_set_post(&syscall_desc[__NR_close], post_close_hook);

        /* start execution */
        libdft_start();

	fclose(taint_file);

        /* typically not reached; make the compiler happy */
        return EXIT_SUCCESS;

err:
        /* error handling */

        /* detach from the process */
        libdft_die();

        /* return */
        return EXIT_FAILURE;
}

