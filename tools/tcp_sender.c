/*
 * server.c -- a stream socket server
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#define MYPORT          3490    /* the port users will be connecting to */
#define BACKLOG         10      /* how many pending connections queue will hold */
#define BUF_SZ          65536   /* chunk size */


int main(int argc, char **argv) {

	int sfd, cfd;                   /* listen on sfd, new connection on cfd */
	int n;                          /* byte counter */
	struct sockaddr_in server_addr; /* my address information */
	struct sockaddr_in client_addr; /* connector's address information */
	socklen_t sin_size;
	int yes                 = 1;
        //char buf[BUF_SZ];             /* chunk buffer */
	char *buf;
	FILE *f;                        /* file handler */
	int i=0;                        /* identifier for # of files to send*/
        //int idx=0;                    /* index in the buffer read from the file */
	int PK_SZ;                      /* packet size for send() */

	PK_SZ = atoi(argv[2]);
        printf("Packet_size: %d\n", PK_SZ);

        //allocate memory to contain the whole file
        buf = (char*) (malloc(sizeof(char)*PK_SZ));
        if(buf == NULL)
        {
                fputs("Malloc error \n", stderr);
                exit(2);
        }

        /* get a new socket */
        if ((sfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
                perror("socket");
                exit(1);
        }

        /* reuse the address */
        if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
                perror("setsockopt");
                exit(1);

        }
        if(setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(int)) == -1)
        {
                perror("setsockopt");
                exit(1);
        }

        memset(&server_addr, 0, sizeof(server_addr));     // zero the rest of the struct
        server_addr.sin_family          = PF_INET;                      // host byte order
        server_addr.sin_port            = htons(MYPORT);                // short, network byte order
        server_addr.sin_addr.s_addr     = INADDR_ANY;                   // automatically fill with my IP

        /* bind */
        if (bind(sfd, (struct sockaddr *)&server_addr,
                        sizeof(struct sockaddr)) == -1) {
                perror("bind");
                exit(1);
        }

        /* listen */
        if (listen(sfd, BACKLOG) == -1) {
                perror("listen");
                exit(1);
        }
         

	sin_size = sizeof(client_addr);
	while((cfd = accept(sfd, (struct sockaddr *)&client_addr,
                                                        &sin_size)) != -1) {


                /* open the filename to send */
                if ((f = fopen(argv[1], "r")) == NULL) {
                        perror("fopen");
                        return EXIT_FAILURE;
                }
		for(i=0;i<3;i++)
		{

                /* clear the buffer */
                (void)memset(buf, 0, PK_SZ);

                /* copy the file to the buffer */
                n = fread(buf, 1, PK_SZ, f);
                if(n != PK_SZ)
                {
                        fputs("Reading error", stderr);
                        exit(3);
                }
                //printf("the buf just read is %s\n", buf);
                //printf("strlen(buf): %d\n", strlen(buf));
                buf[n]='\0';
                //printf("buf[0]= %c\n", buf[0]);
                //printf("strlen(buf): %d\n", strlen(buf));
                //printf("sizeof(buf): %d\n", sizeof(buf));
                printf("n=%d read from the file\n", n);

                if(strcmp(buf, "")!=0)
                {
			send(cfd, buf, PK_SZ, 0);
			//write(cfd, buf, PK_SZ);
                } /*end-of-if*/
		}//end-of-for
                fclose(f);
                free(buf);

                /* terminate the connection with the client */
                (void)close(cfd);
        }

        /* release the binded port */
        (void)close(sfd);

        return EXIT_SUCCESS;
}
