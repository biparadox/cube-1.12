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
#include "session_msg.h"
#include "user_info.h"

extern struct timeval time_val={0,50*1000};

int white_filter_init(void * sub_proc,void * para)
{
	int ret;
	// add youself's plugin init func here
	return 0;
}

int white_filter_start(void * sub_proc,void * para)
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
		proc_block_message1(sub_proc,recv_msg);
	}

	return 0;
};

int proc_block_message1(void * sub_proc,void * message)
{
	const char * type;
	int i;
	int ret;
	int send_no;
	printf("begin proc echo \n");
	struct message_box * msg_box=message;
	type=message_get_recordtype(message);

	struct message_box * new_msg;
	struct session_msg * record;
	struct user_black * black_list;
	
	i=0;
	send_no=0;

	ret=message_get_record(message,&record,i++);
	if(ret<0)
		return ret;
	while(record!=NULL)
	{
		ret=FindPolicy(record->sender,"UB_I",&black_list);
		if (ret<0)
			return ret;
		else if(black_list)
		{
			if(send_no==0)
				new_msg=message_create(type,message);
			send_no++;
			message_add_record(new_msg,record);
		}
		else
			printf("not in white list\n");

		ret=message_get_record(message,&record,i++);
		if(ret<0)
			return ret;
	}
	if(send_no!=0)
		sec_subject_sendmsg(sub_proc,new_msg);
	return ret;
}
