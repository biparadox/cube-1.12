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
#include <sys/un.h>
//#include <time.h>

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/crypto_func.h"
#include "../include/extern_struct.h"
#include "../include/extern_defno.h"
#include "../include/message_struct.h"
#include "../include/logic_baselib.h"
#include "../include/sec_entity.h"
#include "../include/main_proc_init.h"
#include "../include/valuename.h"
#include "../include/expand_define.h"

#include "../cloud_config.h"
#include "main_proc_func.h"

int proc_time_stamp(void * sub_proc,void * message);
int time_stamp_init(void * sub_proc,void * para)
{
	int ret;
	// add youself's plugin init func here
	return 0;
}

int time_stamp_start(void * sub_proc,void * para)
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
		proc_time_stamp(sub_proc,recv_msg);
	}

	return 0;
};

int proc_time_stamp(void * sub_proc,void * message)
{
	const char * type;
	int i;
	int ret;
	struct expand_time_stamp * time_stamp;
	time_t tm;
	char * timestr;
	printf("begin proc time_stamp \n");
	time_stamp=malloc(sizeof(struct expand_time_stamp));
	if(time_stamp==NULL)
		return -ENOMEM;
	memcpy(time_stamp->tag,"TIME",4);
	time_stamp->data_size=sizeof(struct expand_time_stamp);

	time(&tm);
	timestr=ctime_r(&tm,time_stamp->time);

	if(timestr<=0)
		return -EINVAL;
	message_add_expand(message,time_stamp);
	sec_subject_sendmsg(sub_proc,message);
	return ret;
}
