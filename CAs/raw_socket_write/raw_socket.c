#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>

//TODO fis this to point to the real path
const char *sock_path = "/tmp/open_tee_sock";

int main(void)
{
	int sockfd;
	ssize_t n;
	char buff[10];
	struct sockaddr_un sock_addr;

	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		printf("Error in socket open: %s", strerror(errno));
		exit(1);
	}

	memset(&sock_addr, 0, sizeof(struct sockaddr_un));
	strncpy(sock_addr.sun_path, sock_path, sizeof(sock_addr.sun_path) - 1);
	sock_addr.sun_family = AF_UNIX;

	if (connect(sockfd, (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_un)) == -1) {
		printf("Error in socket connect: %s", strerror(errno));
		exit(1);
	}

	while ((n = read(STDIN_FILENO, buff, sizeof(buff) - 1)) > 0) {
		buff[n] = '\0';
		if (write(sockfd, buff, n) == -1) {
			printf("Error in socket connect: %s", strerror(errno));
			exit(1);
		}
	}
	return 0;
}
