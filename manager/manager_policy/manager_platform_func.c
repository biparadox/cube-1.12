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
#include "../include/policy_ui.h"

#include "cloud_config.h"
#include "manager_vm_func.h"
#include "local_func.h"

int manager_platform_init(void * sub_proc,void * para)
{
	int ret;
	char local_uuid[DIGEST_SIZE*2];
	
	return 0;
}

int manager_platform_start(void * sub_proc,void * para)
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
	printf("begin platform manager process!\n");

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
		if(strncmp(type,"PLAI",4)==0)
		{
			proc_store_platform(sub_proc,recv_msg);
		}
		if(strncmp(type,"PLAP",4)==0)
		{
			proc_store_platform_policy(sub_proc,recv_msg);
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
			if(strncmp(req->tag,"PLAI",4)==0)
			{
				proc_send_platform_info(sub_proc,recv_msg);
			}
			else if(strncmp(req->tag,"PLAP",4)==0)
			{
				proc_send_platform_policy(sub_proc,recv_msg);
			}
		}
	}

	return 0;
}
#define MAX_RECORD_NUM 100

int proc_store_platform(void * sub_proc,void * message)
{
	MESSAGE_HEAD * message_head;
	struct platform_info * platform;
	int retval;
	int count=0;
	int i;

		// monitor send a new vm message
  	platform = NULL;
	int ifuuidempty=0;
	for(i=0;i<MAX_RECORD_NUM;i++)
	{
		retval=message_get_record(message,&platform,i);
		if(retval<0)
			break;
		if(platform==NULL)
			break;
		struct platform_info * oldplatform;
		
		printf("policy server receive platform  %s's info from monitor!\n",platform->uuid);
		if(platform->uuid[0]!=0)
		{
			ifuuidempty=1;
			FindPolicy(platform->uuid,"PLAI",&oldplatform);
			if(oldplatform!=NULL)
			{
				printf("this platform already in the PLAI lib!\n");
				continue;
			}
			AddPolicy(platform,"PLAI");
			continue;
		}
		GetFirstPolicy(&oldplatform,"PLAI");
		while(oldplatform!=NULL)
		{
			if(!strncmp(oldplatform->name,platform->name,DIGEST_SIZE*2))
			{
				
				strncpy(platform->uuid,oldplatform->uuid,DIGEST_SIZE*2);
				DelPolicy(oldplatform->uuid,"PLAI");
				AddPolicy(platform,"PLAI"); 
				break;
			}
			GetNextPolicy(&oldplatform,"PLAI");
		}
		if(oldplatform==NULL)
		{
			printf("Can't find this platform,perhaps it is not running?"); 
		}
	}
		// send a message to manager_trust
	retval=ExportPolicyToFile("./lib/PLAI.lib","PLAI");
		// send a message to manager_trust
	return count;
}

int proc_store_platform_policy(void * sub_proc,void * message)
{
	MESSAGE_HEAD * message_head;
	struct vm_policy * policy;
	int retval;
	int ret;
	int count=0;
	int i;
	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	void * send_pcr_msg;
	
	ret=proc_share_data_getvalue("uuid",local_uuid);
	if(ret<0)
		return ret;
	ret=proc_share_data_getvalue("proc_name",proc_name);

	if(ret<0)
		return ret;
	printf("begin platform policy process!\n");

		// monitor send a new vm message
  	policy = NULL;
	for(i=0;i<MAX_RECORD_NUM;i++)
	{
		retval=message_get_record(message,&policy,i);
		if(retval<0)
			break;
		if(policy==NULL)
			break;
		void * oldpolicy;
		printf("policy server receive vm  %s's info from monitor!\n",policy->uuid);
		FindPolicy(policy->uuid,"PLAP",&oldpolicy);
		if(oldpolicy==NULL)
		{
			AddPolicy(policy,"PLAP");
		}
		send_pcr_msg=message_create("PCRP",NULL);
		struct tcm_pcr_set * pcrpolicy;
		FindPolicy(policy->boot_pcr_uuid,"PCRP",&pcrpolicy);
		if(pcrpolicy!=NULL)
		{
			message_add_record(send_pcr_msg,pcrpolicy);
		}
		FindPolicy(policy->runtime_pcr_uuid,"PCRP",&pcrpolicy);
		if(pcrpolicy!=NULL)
		{
			message_add_record(send_pcr_msg,pcrpolicy);
		}
       		sec_subject_sendmsg(sub_proc,send_pcr_msg);
	}
		// send a message to manager_trust
	retval=ExportPolicyToFile("./lib/PLAP.lib","PLAP");
		// add the p
	sec_subject_sendmsg(sub_proc,message);
	
	return count;
}

int proc_send_platform_info(void * sub_proc,void * message)
{
	MESSAGE_HEAD * message_head;
	struct platform_info * platform;
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
	printf("begin send platform info process!\n");

	void * send_msg;
	

		// monitor send a new vm message
//	memset(vm,0,sizeof(struct vm_policy));
  	platform = NULL;
	send_msg=message_create("PLAI",message);
	if(send_msg==NULL)
		return -EINVAL;
	GetFirstPolicy(&platform,"PLAI");
	while( platform != NULL)
	{
		message_add_record(send_msg,platform);
    		GetNextPolicy(&platform,"PLAI");
	}
	sec_subject_sendmsg(sub_proc,send_msg);
	
	return;
}

int proc_send_platform_policy(void * sub_proc,void * message)
{
	struct vm_policy * platform;
	struct request_cmd * cmd;
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
	printf("begin send platform policy process!\n");

	void * send_msg;
	void * send_pcr_msg;
	

	ret=message_get_record(message,&cmd,0);
	if(ret<0)
		return -EINVAL;

		// monitor send a new vm message
//	memset(vm,0,sizeof(struct vm_policy));
  	platform = NULL;
	FindPolicy(cmd->uuid,"PLAP",&platform);
	if(platform==NULL)
		return 0;
	send_msg=message_create("PLAP",message);
	if(send_msg==NULL)
		return -EINVAL;
	message_add_record(send_msg,platform);
	sec_subject_sendmsg(sub_proc,send_msg);
	
	send_pcr_msg=message_create("PCRP",NULL);
	struct tcm_pcr_set * pcrpolicy;
	FindPolicy(platform->boot_pcr_uuid,"PCRP",&pcrpolicy);
	if(pcrpolicy!=NULL)
	{
		message_add_record(send_pcr_msg,pcrpolicy);
       		sec_subject_sendmsg(sub_proc,send_pcr_msg);
	}
	return;
}
/*
int proc_send_platformpolicy_req(void * sub_proc,void * message,void * pointer)
{
	MESSAGE_HEAD * message_head;
	struct request_cmd * cmd;
	char * vm_uuid=pointer;
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
	printf("begin to send platform policy request!\n");

	void * send_msg;
	

	message_head=get_message_head(message);
	if(message_head==NULL)
		return -EINVAL;

		// monitor send a new vm message
//	memset(vm,0,sizeof(struct vm_policy));
	send_msg=message_create("REQC");
	if(send_msg==NULL)
		return -EINVAL;
    	cmd=(struct request_cmd *)malloc(sizeof(struct request_cmd));
   	if(cmd==NULL)
   	memset(cmd,0,sizeof(struct request_cmd));
    	memcpy(cmd->tag,"PLAP",4);
    	strncpy(cmd->uuid,vm_uuid,DIGEST_SIZE*2);
        ret=message_add_record(send_msg,cmd);
        sec_subject_sendmsg(sub_proc,send_msg);
	return 0;
}*/
