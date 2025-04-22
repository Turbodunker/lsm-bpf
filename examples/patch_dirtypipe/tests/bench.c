#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/time.h>


#ifndef BUFFER_SIZE
#define BUFFER_SIZE (1024 * 64)
#endif


int main(int argc, char **argv)
{
	if(argc != 3){
		fprintf(stderr, "Usage: <inputfile> <outputfile>\n");
	}
	
	const char *const input = argv[1];
	const char *const output = argv[2];

	int fd_in, fd_out, fd_tmp, fd_pipe[2];

	fd_in = open(input, O_RDONLY);

	if(fd_in == -1){
		fprintf(stderr, "could not open input file\n");
		return EXIT_FAILURE;
	}


	// needed for random I/O operation to trigger file_permission hook
	fd_tmp = open("/home/mblom/tests/readme", O_RDONLY);
	if(fd_tmp == -1){
		fprintf(stderr, "could not open input file\n");
		close(fd_in);
		return EXIT_FAILURE;
	}

	if(pipe(fd_pipe) == -1){
		fprintf(stderr, "could not create pipe\n");
		close(fd_in);
		close(fd_tmp);
		return EXIT_FAILURE;
	}


	fd_out = open(output, O_WRONLY);
	if(fd_out == -1){
		fprintf(stderr, "could not open output file");
		close(fd_pipe[0]);
		close(fd_pipe[1]);
		close(fd_in);
		close(fd_tmp);
		return EXIT_FAILURE;
	}
	loff_t loff_in = 0; 
	loff_t loff_out = 0; 
	static char* buffer[4096];
	for(int i = 0; i < 10000; i++){

		
		long data_in = splice(fd_in, &loff_in, fd_pipe[1], NULL, BUFFER_SIZE, 0);
		if(data_in <= 0){
			fprintf(stderr, "splice 1 failed\n");
			return EXIT_FAILURE;
		}
		long data_out = splice(fd_pipe[0], NULL, fd_out, NULL, data_in, 0);	
		if(data_out <= 0){
			fprintf(stderr, "splice 2 failed\n");
			return EXIT_FAILURE;
		}

		/* some read some random file to trigger file_permission hook */

		long data = read(fd_tmp, buffer, sizeof(buffer));
		if(data <= 0){
			fprintf(stderr, "read failed\n");
			return EXIT_FAILURE;
		}
		long ret = write(fd_out, buffer, sizeof(buffer));
		if(data <= 0){
			fprintf(stderr, "write failed\n");
			return EXIT_FAILURE;
		}
	}
	close(fd_pipe[0]);
	close(fd_pipe[1]);
	close(fd_in);
	close(fd_tmp);
	close(fd_out);
	fprintf(stderr, "success!\n");
	return EXIT_SUCCESS;
}
