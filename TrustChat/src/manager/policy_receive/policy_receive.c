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

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/crypto_func.h"
#include "../include/extern_struct.h"
#include "../include/extern_defno.h"
#include "../include/message_struct.h"
#include "../include/logic_baselib.h"
#include "../include/sec_entity.h"
//#include "../include/main_proc_init.h"
#include "../include/valuename.h"
#include "../include/expand_define.h"


struct policy_rule
{
	char proc_name[DIGEST_SIZE];
	int  policy_size;
	char * policy_data;
}__attribute__((packed));

extern struct timeval time_val={0,50*1000};

int policy_receive_init(void * sub_proc,void * para)
{
	int ret;
	// add youself's plugin init func here
	return 0;
}

int policy_receive_start(void * sub_proc,void * para)
{
	int ret;
	void * recv_msg;
	int i;
	const char * type;


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
			printf("message format error!\n");
			continue;
		}
		if(!find_record_type(type))
		{
			printf("message format is not registered!\n");
			continue;
		}
		if(strncmp(type,"POLI",4)==0)
		{
			proc_policy_receive(sub_proc,recv_msg);
		}
	}

	return 0;
};

int proc_policy_receive(void * sub_proc,void * message)
{
	const char * type;
	int i;
	int ret;
	printf("begin proc echo \n");
	struct message_box * msg_box=message;
	type=message_get_recordtype(message);

	struct policy_rule * record;
	
	i=0;

	ret=message_get_record(message,&record,i++);
	if(ret<0)
		return ret;
	while(record!=NULL)
	{
		char dirname[DIGEST_SIZE*2];
		char policyfile[DIGEST_SIZE*4];
		char backfile[DIGEST_SIZE*4];
		char buffer[DIGEST_SIZE*8];
		sprintf(dirname,"../%s",record->proc_name);
		sprintf(policyfile,"%s/router_policy.cfg",dirname);
		sprintf(backfile,"%s/router_policy.cfg.bak",dirname);
		sprintf(buffer,"cp %s %s",policyfile,backfile);
		system(buffer);
		sleep(1);
		int fd;
		int fd1;
		fd=open(policyfile,O_WRONLY | O_TRUNC);
		if(fd<0)
		{
			printf("open policyfile %s error!\n",policyfile);
			return -EINVAL;
		}
		write(fd,record->policy_data,record->policy_size);

		fd1=open(backfile,O_RDONLY);
		if(fd1<0)
		{
			printf("open backfile %s error!\n",backfile);
			return -EINVAL;
		}
		write(fd,"\n",1);
		while((ret=read(fd1,buffer,DIGEST_SIZE*8))>0)
		{
			write(fd,buffer,ret);
			if(ret<DIGEST_SIZE*8)
				break;	
		}
		if(ret<0)
			return ret;
		close(fd);
		close(fd1);
		
		ret=message_get_record(message,&record,i++);
		if(ret<0)
			return ret;
	}
	return ret;
}
