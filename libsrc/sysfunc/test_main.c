
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>


#include "../include/data_type.h"
#include "../include/sysfunc.h"


BYTE Blob[4096];
char text[4096];

static void
bail(const char *on_what) {
	perror(on_what);
	exit(1);
}


int main()
{
	char uuid[DIGEST_SIZE*2];

	int len;
	len=get_local_uuid(uuid);
	printf("%d %s\n",len,uuid);

	return 0;
}
