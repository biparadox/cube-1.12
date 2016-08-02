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
#include "../include/message_struct.h"
#include "../include/logic_baselib.h"
#include "../include/sec_entity.h"
#include "../include/main_proc_init.h"
#include "../include/valuename.h"
#include "../include/expand_define.h"
#include "session_msg.h"

#include "key_storage.h"

int key_storage_init(void * sub_proc,void * para)
{
	int ret;
	// add youself's plugin init func here
	return 0;
}

int key_storage_start(void * sub_proc,void * para)
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
		if(strncmp(type,"NKLD",4)==0)
			proc_key_storage(sub_proc,recv_msg);
		else if(strncmp(type,"KREC",4)==0)
			proc_key_response(sub_proc,recv_msg);
	}

	return 0;
};

int proc_key_storage(void * sub_proc,void * message)
{
	const char * type;
	int i;
	int ret;
	printf("begin proc echo \n");
	struct message_box * msg_box=message;

	void * record;
	
	i=0;

	ret=message_get_record(message,&record,i++);
	if(ret<0)
		return ret;
	while(record!=NULL)
	{
		AddPolicy(record,"NKLD");
		ret=message_get_record(message,&record,i++);
		if(ret<0)
			return ret;
	}
	ExportPolicy("NKLD");
	return ret;
}
int proc_key_response(void * sub_proc,void * message)
{
	const char * type;
	int i;
	int ret;
	struct message_box * msg_box=message;
	struct node_key_list * pub_keylist;

	void * new_msg;
	struct key_request_cmd * reqdata;
	char uuidname[DIGEST_SIZE*2+16];
	ret=message_get_record(message,&reqdata,0);
	if(ret<0)
		return ret;
	if(reqdata== NULL)
		return 0;

		
	ret=GetFirstPolicy(&pub_keylist,"NKLD");
	if(ret<0)
		return ret;
	while(pub_keylist!=NULL)
	{
		if(strncmp(pub_keylist->username,reqdata->user_name,DIGEST_SIZE)==0)
			break;
		ret=GetNextPolicy(&pub_keylist,"NKLD");
		if(ret<0)
			return ret;
	}
	if(pub_keylist==NULL)
	{
		printf("no user %s's pubkeylist!\n",reqdata->user_name);
		return ret;
	}

	new_msg=message_create("NKLD",message);
	if(new_msg==NULL)
		return -EINVAL;
	message_add_record(new_msg,pub_keylist);
	sec_subject_sendmsg(sub_proc,new_msg);

	sprintf(uuidname,"pubkey/%.64s.pem",pub_keylist->nodeAIK);
	ret=build_filedata_struct(&reqdata,uuidname);
	if(ret>=0)
	{
		new_msg=message_create("FILD",message);
		if(new_msg!=NULL)
		{
			message_add_record(new_msg,reqdata);
			sec_subject_sendmsg(sub_proc,new_msg);
		}
	}
	// share AIKsda
	sprintf(uuidname,"cert/%.64s.sda",pub_keylist->nodeAIKSda);
	ret=build_filedata_struct(&reqdata,uuidname);
	if(ret>=0)
	{
		new_msg=message_create("FILD",message);
		if(new_msg!=NULL)
		{
			message_add_record(new_msg,reqdata);
			sec_subject_sendmsg(sub_proc,new_msg);
		}
	}
	// share Bindkey
	sprintf(uuidname,"pubkey/%.64s.pem",pub_keylist->nodeBindKey);
	ret=build_filedata_struct(&reqdata,uuidname);
	if(ret>=0)
	{
		new_msg=message_create("FILD",message);
		if(new_msg!=NULL)
		{
			message_add_record(new_msg,reqdata);
			sec_subject_sendmsg(sub_proc,new_msg);
		}
	}
	// share Bindkeyval
	sprintf(uuidname,"cert/%.64s.val",pub_keylist->nodeBindKeyVal);
	ret=build_filedata_struct(&reqdata,uuidname);
	if(ret>=0)
	{
		new_msg=message_create("FILD",message);
		if(new_msg!=NULL)
		{
			message_add_record(new_msg,reqdata);
			sec_subject_sendmsg(sub_proc,new_msg);
		}
	}

	return 0;
}
