#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <mysql/mysql.h>
#include <errno.h>
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
#include "../include/vmlist.h"
#include "../include/vm_policy.h"
#include "../include/connector.h"
#include "../include/logic_baselib.h"
#include "../include/connector.h"
#include "../include/sec_entity.h"

#include "readconfig.h"
#include "local_func.h"

int proc_send_reqcmd(void * sub_proc,char * receiver,void * para)
{
	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	char * cmd_type=para;
	int  ret;
	
	ret=proc_share_data_getvalue("uuid",local_uuid);
	if(ret<0)
		return ret;
	ret=proc_share_data_getvalue("proc_name",proc_name);

	if(ret<0)
		return ret;
	printf("begin send %s reqcmd!\n",cmd_type);
    	void * send_msg;
    	send_msg=message_create("REQC");
    	struct request_cmd * cmd;
    	cmd=(struct request_cmd *)malloc(sizeof(struct request_cmd));
   	if(cmd==NULL)
   	memset(cmd,0,sizeof(struct request_cmd));
    	memcpy(cmd->tag,para,4);
        ret=message_add_record(send_msg,cmd);
        sec_subject_sendmsg(sub_proc,send_msg);
	return 0;
}



int proc_send_compute_localinfo(void * sub_proc,void * message,void * para)
{
	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	char hostname[DIGEST_SIZE*2+1];
	int  ret;
	MESSAGE_HEAD * message_head;
    	struct platform_info * platform;
	message_head=get_message_head(message);
	if(message_head==NULL)
		return -EINVAL;	
	ret=proc_share_data_getvalue("uuid",local_uuid);
	if(ret<0)
		return ret;
	ret=proc_share_data_getvalue("proc_name",proc_name);
	if(ret<0)
		return ret;
	ret=proc_share_data_getvalue("hostname",hostname);
	if(ret<0)
		return ret;

	printf("begin send %s localinfo!\n",hostname);

	ret=message_get_record(message,&platform,0);
	if(ret<0)
		return -EINVAL;
	if(platform==NULL)
		return -EINVAL;

    	memcpy(platform->uuid,local_uuid,DIGEST_SIZE*2);
	void * send_msg;
	send_msg=message_create("PLAI");
	message_add_record(send_msg,platform);
        sec_subject_sendmsg(sub_proc,send_msg);
	return 0;
}



