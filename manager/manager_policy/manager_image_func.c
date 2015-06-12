#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
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

#include "cloud_config.h"
#include "manager_image_func.h"
#include "local_func.h"


int manager_image_init(void * sub_proc,void * para)
{
	int ret;
	char local_uuid[DIGEST_SIZE*2];
	
	return 0;
}

int manager_image_start(void * sub_proc,void * para)
{
	int ret;
	int retval;
	void * context;
	int i;
	void * recv_msg;

	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	const char * type;
	
	ret=proc_share_data_getvalue("uuid",local_uuid);
	if(ret<0)
		return ret;
	ret=proc_share_data_getvalue("proc_name",proc_name);

	if(ret<0)
		return ret;
	printf("begin image manager process!\n");

	for(i=0;i<500*1000;i++)
	{
		usleep(time_val.tv_usec);
		ret=sec_subject_recvmsg(sub_proc,&recv_msg);
		if(ret<0)
			continue;
		if(recv_msg==NULL)
			continue;
		type=message_get_recordtype(recv_msg);
		if(type==NULL)
			continue;
		if(strncmp(type,"IMGI",4)==0)
		{
			proc_store_image(sub_proc,recv_msg);
		}
		if(strncmp(type,"IMGP",4)==0)
		{
			proc_store_image_policy(sub_proc,recv_msg);
		}
		if(strncmp(type,"PCRP",4)==0)
		{
			proc_store_pcr_policy(sub_proc,recv_msg);
		}
		if(strncmp(type,"REQC",4)==0)
		{
			struct request_cmd * req;
			ret=message_get_record(recv_msg,&req,0);
			if(ret<0)
			{
				printf("error request command!\n");
				continue;
			}
			if(strncmp(req->tag,"IMGI",4)==0)
			{
				proc_send_image_info(sub_proc,recv_msg);
			}
			else if(strncmp(req->tag,"IMGP",4)==0)
			{
				proc_send_image_policy(sub_proc,recv_msg);
			}
		}
	}

	return 0;
}
#define MAX_RECORD_NUM 100

int proc_store_image(void * sub_proc,void * message)
{
	MESSAGE_HEAD * message_head;
	struct image_info * image;
	int retval;
	int count=0;
	int i;

		// monitor send a new vm message
//	memset(vm,0,sizeof(struct vm_info));
  	image = NULL;
	for(i=0;i<MAX_RECORD_NUM;i++)
	{
		retval=message_get_record(message,&image,i);
		if(retval<0)
			break;
		if(image==NULL)
			break;
		void * oldimage;
		printf("policy server receive image %s's info from monitor!\n",image->uuid);
		FindPolicy(image->uuid,"IMGI",&oldimage);
		if(oldimage!=NULL)
		{
			printf("this image already in the IMGI lib!\n");
			continue;
		}
		AddPolicy(image,"IMGI");
	}
		// send a message to manager_trust
	retval=ExportPolicyToFile("./lib/IMGI.lib","IMGI");
		// send a message to manager_trust
	return count;
}

int proc_store_image_policy(void * sub_proc,void * message)
{
	MESSAGE_HEAD * message_head;
	struct vm_policy * image;
	int retval;
	int ret;
	int count=0;
	int i;
	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	
	ret=proc_share_data_getvalue("uuid",local_uuid);
	if(ret<0)
		return ret;
	ret=proc_share_data_getvalue("proc_name",proc_name);

	if(ret<0)
		return ret;
	printf("begin image policy process!\n");

		// monitor send a new vm message
//	memset(vm,0,sizeof(struct vm_policy));
  	image = NULL;
	for(i=0;i<MAX_RECORD_NUM;i++)
	{
		retval=message_get_record(message,&image,i);
		if(retval<0)
			break;
		if(image==NULL)
			break;
		void * oldimage;
		printf("policy server receive image  %s's info from monitor!\n",image->uuid);
		FindPolicy(image->uuid,"IMGP",&oldimage);
		if(oldimage!=NULL)
		{
			printf("this image's policy  already in the IMGP lib!\n");
			continue;
		}
		AddPolicy(image,"IMGP");
	}
		// send a message to manager_trust
	retval=ExportPolicyToFile("./lib/IMGP.lib","IMGP");
		// forward  message to verifier
	return count;
}

int proc_store_pcr_policy(void * sub_proc,void * message)
{
	MESSAGE_HEAD * message_head;
	struct tcm_pcr_set * pcrs;
	int retval;
	int ret;
	int count=0;
	int i;
	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	
	ret=proc_share_data_getvalue("uuid",local_uuid);
	if(ret<0)
		return ret;
	ret=proc_share_data_getvalue("proc_name",proc_name);

	if(ret<0)
		return ret;
	printf("begin pcr policy process!\n");

		// monitor send a new vm message
//	memset(vm,0,sizeof(struct vm_policy));
  	pcrs = NULL;
	for(i=0;i<MAX_RECORD_NUM;i++)
	{
		retval=message_get_record(message,&pcrs,i);
		if(retval<0)
			break;
		if(pcrs==NULL)
			break;
		void * oldpcrs;
		printf("policy server receive pcrs  %s's info from monitor!\n",pcrs->uuid);
		FindPolicy(pcrs->uuid,"PCRP",&oldpcrs);
		if(oldpcrs!=NULL)
		{
			printf("this pcrs policy  already in the PCRP lib!\n");
			continue;
		}
		AddPolicy(pcrs,"PCRP");
	}

	retval=ExportPolicy("PCRP");
	return count;
}

int proc_send_image_info(void * sub_proc,void * message)
{
	MESSAGE_HEAD * message_head;
	struct image_info * image;
	int retval;
	int ret;
	int count=0;
	int i;
	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	
	ret=proc_share_data_getvalue("uuid",local_uuid);
	if(ret<0)
		return ret;
	ret=proc_share_data_getvalue("proc_name",proc_name);

	if(ret<0)
		return ret;
	printf("begin image send image info process!\n");

	void * send_msg;
	

	message_head=get_message_head(message);
	if(message_head==NULL)
		return -EINVAL;

		// monitor send a new vm message
//	memset(vm,0,sizeof(struct vm_policy));

	image=NULL;
	send_msg=message_create("IMGI",message);
	if(send_msg==NULL)
		return -EINVAL;
	GetFirstPolicy(&image,"IMGI");
	while(image!=NULL)
	{
		message_add_record(send_msg,image);
		GetNextPolicy(&image,"IMGI");
	}
	sec_subject_sendmsg(sub_proc,send_msg);
	
	return;
}
int proc_send_image_policy(void * sub_proc,void * message)
{
	MESSAGE_HEAD * message_head;
	struct request_cmd * cmd;
	struct vm_policy * image_policy;
	struct tcm_pcr_set * pcrs;
	int retval;
	int ret;
	int count=0;
	int i;
	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	
	ret=proc_share_data_getvalue("uuid",local_uuid);
	if(ret<0)
		return ret;
	ret=proc_share_data_getvalue("proc_name",proc_name);

	if(ret<0)
		return ret;
	printf("begin image send image policy process!\n");

	void * send_msg;
	void * send_pcr_msg;
	
	message_head=get_message_head(message);
	if(message_head==NULL)
		return -EINVAL;

	ret=message_get_record(message,&cmd,0);
	if(ret<0)
		return -EINVAL;
		// monitor send a new vm message
//	memset(vm,0,sizeof(struct vm_policy));
  	image_policy = NULL;
	FindPolicy(cmd->uuid,"IMGP",&image_policy);
	if( image_policy == NULL)
		return 0;
	send_msg=message_create("IMGP",message);
	if(send_msg==NULL)
		return -EINVAL;
	message_add_record(send_msg,image_policy);
	sec_subject_sendmsg(sub_proc,send_msg);

	send_pcr_msg=message_create("PCRP",message);
	if(send_pcr_msg==NULL)
		return -EINVAL;
	FindPolicy(image_policy->boot_pcr_uuid,"PCRP",&pcrs);
	if(pcrs!=NULL)
		message_add_record(send_pcr_msg,pcrs);
	FindPolicy(image_policy->runtime_pcr_uuid,"PCRP",&pcrs);
	if(pcrs!=NULL)
	{
		message_add_record(send_pcr_msg,pcrs);
		sec_subject_sendmsg(sub_proc,send_pcr_msg);
	}

	return;
}
