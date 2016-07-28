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
#include "../include/main_proc_init.h"
#include "../include/valuename.h"
#include "../include/expand_define.h"

#include "session_msg.h"
#include "user_info.h"
#include "message_expand.h"

int message_expand_init(void * sub_proc,void * para)
{
	int ret;
	// add youself's plugin init func here
	return 0;
}

int message_expand_start(void * sub_proc,void * para)
{
	int ret;
	void * recv_msg;
	int i;
	const char * type;

	void * send_msg;
	time_t tm;

	struct session_msg * first_msg;
	struct user_info_list * user_info;
	struct login_info * login;
	

/*
	usleep(500*1000);
	ret=GetFirstPolicy(&user_info,"UL_I");
	if(ret<0)
		return ret;
	login=malloc(sizeof(struct login_info));
	memcpy(login->user,user_info->name,DIGEST_SIZE);
	memcpy(login->passwd,user_info->passwd,DIGEST_SIZE);
	send_msg=message_create("LOGI",NULL);
	if(send_msg==NULL)
		return -EINVAL;
	message_add_record(send_msg,login);
//	ret=sec_subject_sendmsg(sub_proc,send_msg);
	if(ret>=0)
		printf("send first message succeed!\n");
	usleep(2000*1000);


	ret=GetFirstPolicy(&first_msg,"MSGD");
	if(ret<0)
		return -EINVAL;

	ret=DelPolicy(first_msg->uuid,"MSGD");
	if(ret<0)
		return -EINVAL;
	time(&tm);
	first_msg->time=tm;

	ret=entity_hash_uuid("MSGD",first_msg);
	if(ret<0)
		return ret;
	
	AddPolicy(first_msg,"MSGD");
	

	send_msg=message_create("MSGD",NULL);
	if(send_msg==NULL)
		return -EINVAL;
	message_add_record(send_msg,first_msg);
        if(first_msg->flag==MSG_PRIVATE){
        	struct user_name_expand  *eei;
        	eei =malloc(sizeof(struct user_name_expand));
        	if(eei==NULL)
                	return -ENOMEM;
                memset(eei->name,0,DIGEST_SIZE);
                memcpy(eei->name,first_msg->receiver,DIGEST_SIZE);
                eei->data_size=sizeof(struct user_name_expand );
                memcpy(eei->tag,"USNE",4);
                message_add_expand(send_msg,eei);
	}

//	ret=sec_subject_sendmsg(sub_proc,send_msg);
	if(ret>=0)
		printf("send second message succeed!\n");
*/	

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
		if(strncmp(type,"MSGD",4)==0)
			proc_expand_message(sub_proc,recv_msg);
		//if(strncmp(type,"LOGI",4)==0)
		//	proc_echo_message(sub_proc,recv_msg);
	}

	return 0;
};

int proc_expand_message(void * sub_proc,void * message)
{
	const char * type;
	int i;
	int ret;
	printf("begin proc echo \n");
	struct message_box * msg_box=message;

	struct message_box * new_msg;
	struct session_msg * echo_msg;
	time_t tm;
         
	ret=message_get_record(message,&echo_msg,0);
	if(echo_msg==NULL)
		return 0;
	
	time(&tm);
	echo_msg->time=tm;

	ret=entity_hash_uuid("MSGD",echo_msg);
	if(ret<0)
		return ret;
	
	new_msg=message_create("MSGD",message);
	
        if(echo_msg->flag==MSG_PRIVATE){
        	struct user_name_expand  *eei;
        	eei =malloc(sizeof(struct user_name_expand));
        	if(eei==NULL)
                	return -ENOMEM;
                memset(eei->name,0,DIGEST_SIZE);
                memcpy(eei->name,echo_msg->receiver,DIGEST_SIZE);
                eei->data_size=sizeof(struct expand_extra_info );
                memcpy(eei->tag,"USNE",4);
                message_add_expand(new_msg,eei);
	}
	message_add_record(new_msg,echo_msg);
	sec_subject_sendmsg(sub_proc,new_msg);
	return ret;
}
