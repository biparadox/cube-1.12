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

int send_int_array(char * name,int num,int * array,void * sub_proc)
{
	struct visual_data * data;
	int i;
	int ret;
	struct message_box * new_msg;
	new_msg=message_create("INTD",NULL);
	if(new_msg==NULL)
		return -EINVAL;
	for(i=0;i<num;i++)
	{
		data=malloc(sizeof(struct visual_data));
		if(data==NULL)
			return -ENOMEM;
	
		memset(data,0,sizeof(*data));
		data->name=dup_str(name,0);	
		
		data->type=DATA_INIT;
		data->index=0;
		data->value=array[i];
		message_add_record(new_msg,data);
	}
	sec_subject_sendmsg(sub_proc,new_msg);
	return num;
}

int send_index_array(char * name,enum data_type type, int num,int * index,void * sub_proc)
{
	struct visual_data * data;
	int i;
	int ret;
	struct message_box * new_msg;
	new_msg=message_create("INTD",NULL);
	if(new_msg==NULL)
		return -EINVAL;
	for(i=0;i<num;i++)
	{
		data=malloc(sizeof(struct visual_data));
		if(data==NULL)
			return -ENOMEM;
	
		memset(data,0,sizeof(*data));
		data->name=dup_str(name,0);	
		data->type=type;
		data->index=index[i];
		message_add_record(new_msg,data);
	}
	sec_subject_sendmsg(sub_proc,new_msg);
	return num;
}
