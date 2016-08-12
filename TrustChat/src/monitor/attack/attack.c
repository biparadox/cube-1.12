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
#include "user_info.h"
#include "session_msg.h"

extern struct timeval time_val={0,50*1000};

int attack_init(void * sub_proc,void * para)
{
	int ret;
	// add youself's plugin init func here
	return 0;
}

int attack_start(void * sub_proc,void * para)
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
		if(strncmp(type,"REQC",4)==0)
			proc_flush_msg(sub_proc,recv_msg);
	}

	return 0;
};

int proc_flush_msg(void * sub_proc,void * message)
{

	struct user_info_list * hackers;
	const char * type;
	int i;
	int ret;
	time_t tm;
	printf("begin proc flush \n");

	struct session_msg * flush_msg;

	void * new_msg;
	
	ret=GetFirstPolicy(&hackers,"UL_I");
	if(ret<0)
		return ret;
	while(hackers!=NULL)
	{
		new_msg=message_create("MSGD",message);
		flush_msg=malloc(sizeof(*flush_msg));
		if(flush_msg==NULL)
			return -ENOMEM;
		memset(flush_msg,0,sizeof(*flush_msg));
		time(&tm);
		flush_msg->time=tm;
		flush_msg->flag=MSG_GENERAL;
		strncpy(flush_msg->sender,hackers->name,DIGEST_SIZE);	
		flush_msg->msg=dup_str("We are hackers!",0);	
		ret=entity_hash_uuid("MSGD",flush_msg);
		if(ret<0)
			return ret;
		message_add_record(new_msg,flush_msg);
		sec_subject_sendmsg(sub_proc,new_msg);
		ret=GetNextPolicy(&hackers,"UL_I");
	}

	return 0;
}
