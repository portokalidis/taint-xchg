/*
** client.c -- a stream socket client demo
*/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>		/* for fork() */
#include <errno.h>
#include <string.h>
#include <sched.h>		/* for sched_getaffinity(), sched_setscheduler*/
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/param.h>
#include <sys/types.h>		/* for fork(), wait4() */
#include <sys/time.h>		/* for  rdtsc */
#include <time.h>
#include <sys/resource.h>       /* for struct rusage, wait4() */

#define PORT 3490 // the port client will be connecting to 

#define BILLION 1000000000L

/************************************************************************
 * 									*
 * 			 TCP/IP client					*
 * 			 						*
 *  Usage: ./tcp_client_file_rdtsc  host  inputFile			*
 *					size-of-file	log-filename	*
 *  									*
 *  host - name of a computer on which server is running		*
 *  inputFile - name of file expected					*
 *  size-of-file - byte-size of expected file
 *  log-filename - name of logfile where time measurements are written	*
 *  
 *  Note: 								*
 *  If no host is specified, the client uses "localhost"		*
 *  									*
 ***********************************************************************/
#define BUF_SZ 2048//16384	 // max number of bytes we can get at once

int main(int argc, char *argv[])
{
	int sockfd;			/* socket descriptor */ 
	char buf[BUF_SZ];
	int MAXDATASIZE;		/* File0size transfer */
	int bytes_recv = 0;		/* byte counter */
	int total_bytes_recv = 0;
	int bytes_left_to_recv;
	//int bytes_in_memory = 0;
	//int bytes_to_file = 0;
	int PK_SZ ;
	int i=0;

	struct hostent *he;
	struct sockaddr_in server_addr; // connector's address information 
	FILE *f1;
	FILE *f2;
	//char *filename = "file_10KB_copy.txt";
	//int count_while=0;


	(void)memset(buf, 0, sizeof(buf));

        if((f1 = fopen(argv[2], "w")) == NULL)
        {
                perror("fopen");
                exit(1);
        }

	if((f2 = fopen("tcp_client_output.txt", "w")) == NULL)
	{
		perror("fopen");
		exit(1);
	}

	if(argc !=4)
	{

		fprintf(stderr,"usage: client server-ip filename file-size(in bytes) log-file\n");
		exit(1);
	}

	if ((he=gethostbyname(argv[1])) == NULL) {  // get the host info 
        	perror("gethostbyname");
        	exit(1);
    	}

	MAXDATASIZE = atoi(argv[3]);
	PK_SZ = MAXDATASIZE;
	bytes_left_to_recv = MAXDATASIZE;

	/*create the socket*/
    	if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) 
	{
        	perror("socket");
        	exit(1);
	}
	//fcntl(sockfd, F_SETFL, O_NONBLOCK);

	server_addr.sin_family = AF_INET;    // host byte order 
	server_addr.sin_port = htons(PORT);  // short, network byte order 
	server_addr.sin_addr = *((struct in_addr *)he->h_addr);
	memset(&(server_addr.sin_zero), '\0', 8);  // zero the rest of the struct 
	/* create connection to the server */
	if (connect(sockfd, (struct sockaddr *)&server_addr,sizeof(struct sockaddr))==-1)
	{
		perror("connect");
		exit(1);
	}

        
	//bytes_recv= recv(sockfd, buf, PK_SZ, MSG_WAITALL);
	for(i=0;i<3; i++)
	//{
		//if((bytes_recv = recv(sockfd, buf, PK_SZ, 0)) > 0)
	//while((bytes_recv = read(sockfd, buf, PK_SZ))>0)//PK_SZ))>0)
	{
		printf("round:%d\n", i);
		if((bytes_recv = recv(sockfd, buf, PK_SZ, 0))>0)
		//if((bytes_recv = read(sockfd, buf,PK_SZ))>0)
		{
			fprintf(f2,"bytes_recv(packet[%d]) = %d\n", i, bytes_recv);
		
		//if(bytes_left_to_recv == MAXDATASIZE)
		//{
			//i++;
		//	printf("Start receiving the %dth packet\n", i);
			
		//}

		//if((bytes_recv = read(sockfd, buf, 10))>0)

		total_bytes_recv = total_bytes_recv + bytes_recv;
		
		fprintf(f2, "Total_bytes_recv till now: %d\n", total_bytes_recv);


		//if(total_bytes_recv <= MAXDATASIZE)
		//{

			fprintf(f2, "Writing packet[%d]: %d bytes to file...\n", i, bytes_recv);
			fwrite(buf, 1, bytes_recv, f1);
			fprintf(f2, "BUF_READ:%s\n", buf);
			//write(f1, buf, bytes_recv);
			(void)memset(buf, 0, 2*MAXDATASIZE);
		//	bytes_left_to_recv = bytes_left_to_recv - bytes_recv;
	//		fprintf(f2, "bytes_left_to_recv: %d\n", bytes_left_to_recv);

			//if(bytes_left_to_recv == 0)
			//{
				//printf("Closing file...\n");
				//fclose(f1);
				
				/*total_bytes_recv = 0;

				bytes_left_to_recv = MAXDATASIZE;*/
			//}
			//else
			//{
			//	printf("bytes_left_to_recv != 0\n");
			//}
		//}
		/*else
		{
			fprintf(f2, "Received :%d bytes\n", total_bytes_recv);
			fwrite(buf, 1, bytes_recv, f1);
			fprintf(f2, "In else:BUF_READ:%s\n",buf);
		}*/
			bytes_recv = 0;
			//sleep(20);
		}
	}//end-of-for
	fclose(f1);
	fclose(f2);
	return 0;
} 
