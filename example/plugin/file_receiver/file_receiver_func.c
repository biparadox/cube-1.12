#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/crypto_func.h"
#include "../include/extern_struct.h"
#include "../include/extern_defno.h"
#include "../include/valuename.h"
#include "../include/message_struct.h"
#include "../include/message_struct_desc.h"
#include "../include/vmlist.h"
#include "../include/vtpm_struct.h"
#include "../include/vm_policy.h"
#include "../include/connector.h"
#include "../include/logic_baselib.h"
#include "../include/connector.h"
#include "../include/sec_entity.h"
#include "../include/main_proc_init.h"

#include "../cloud_config.h"
#include "main_proc_func.h"

int file_receiver_init(void * sub_proc,void * para)
{
	int ret=0;
	return ret;
}

int file_receiver_start(void * sub_proc,void * para)
{
	int ret;
	void * recv_msg;
	void * context;
	int i;
	const char * type;

	printf("begin file_receiver start process! \n");

	for(i=0;i<3000*1000;i++)
	{
		usleep(time_val.tv_usec);
		ret=sec_subject_recvmsg(sub_proc,&recv_msg);
		if(ret<0)
			continue;
		if(recv_msg==NULL)
			continue;

 		type=message_get_recordtype(recv_msg);
		if(type==NULL)
		{
			message_free(recv_msg);
			continue;
		}
		if(strncmp(type,"FILD",4)==0)
		{
			proc_file_receive(sub_proc,recv_msg);
		}
		else
		{
			message_free(recv_msg);
		}
	}

	return 0;
};


int proc_file_receive(void * sub_proc,void * message)
{
	struct policyfile_data * reqdata;
	int ret;

	printf("begin file receive!\n");
	char buffer[1024];
	char digest[DIGEST_SIZE];
	int blobsize=0;
	int fd;

	ret=get_filedata_from_message(message);
	if(ret<0)
		return ret;
	printf("get file succeed!\n");

	return 0;
}
