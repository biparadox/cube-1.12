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

#include "data_type.h"
#include "struct_deal.h"
#include "extern_struct.h"
#include "extern_defno.h"
#include "message_struct.h"
#include "logic_baselib.h"
#include "sec_entity.h"
#include "valuename.h"
#include "expand_define.h"
#include "data_define.h"

extern struct timeval time_val={0,50*1000};

int random_seq_init(void * sub_proc,void * para)
{
	int ret;
	// add youself's plugin init func here
	time_t seeds;
	time(&seeds);
	srand(seeds);
	return 0;
}

int random_seq_start(void * sub_proc,void * para)
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
		proc_echo_message(sub_proc,recv_msg);
	}

	return 0;
};

int proc_echo_message(void * sub_proc,void * message)
{

	struct visual_data * data;
	const char * type;
	int i;
	int ret;
	printf("begin proc random_seq \n");
	struct message_box * msg_box=message;
	type=message_get_recordtype(message);

	for(i=0;i<25;i++)
	{

		struct message_box * new_msg;
		new_msg=message_create("INTD",message);
		if(new_msg==NULL)
			return -EINVAL;
		data=malloc(sizeof(struct visual_data));
		if(data==NULL)
			return -ENOMEM;
	
		memset(data,0,sizeof(*data));
		data->type=DATA_ADD;

		data->index=0;
		data->value=rand()%256;
		
		message_add_record(new_msg,data);
		sec_subject_sendmsg(sub_proc,new_msg);
		sleep(1);
	}
	return ret;
}
