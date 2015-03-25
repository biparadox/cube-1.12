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
#include "manager_vm_func.h"
#include "local_func.h"

int manager_platform_init(void * sub_proc,void * para)
{
	int ret;
	char local_uuid[DIGEST_SIZE*2];
	
//	struct aik_proc_pointer * aik_pointer;
//	main_pointer= kmalloc(sizeof(struct main_proc_pointer),GFP_KERNEL);
	sec_subject_register_statelist(sub_proc,monitor_state_list);

	return 0;
}

int manager_platform_start(void * sub_proc,void * para)
{
	int ret;
	int retval;
	void * message_box;
	void * context;
	int i;
	void * recv_msg;
	void * send_msg;

	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	
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
		MESSAGE_HEAD * msg_head;
		msg_head=get_message_head(recv_msg);
		if(msg_head==NULL)
			continue;
		if(strncmp(msg_head->record_type,"PLAI",4)==0)
		{
			proc_store_platform(sub_proc,recv_msg,NULL);
		}
		if(strncmp(msg_head->record_type,"PLAP",4)==0)
		{
			proc_store_platform_policy(sub_proc,recv_msg,NULL);
		}
		if(strncmp(msg_head->record_type,"REQC",4)==0)
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
				proc_send_platform_info(sub_proc,recv_msg,&send_msg);
				if((msg_head->flow & MSG_FLOW_RESPONSE) &&(send_msg!=NULL) )
				{
					void * flow_expand;
					ret=message_remove_expand(recv_msg,"FTRE",&flow_expand);
					if(flow_expand!=NULL) 
					{
						message_add_expand(send_msg,flow_expand);
					}
					else
					{
						set_message_head(send_msg,"receiver_uuid",msg_head->sender_uuid);
					}
				}
				sec_subject_sendmsg(sub_proc,send_msg);
			}
			else if(strncmp(req->tag,"PLAP",4)==0)
			{
				proc_send_platform_policy(sub_proc,recv_msg,&send_msg);
				if((msg_head->flow & MSG_FLOW_RESPONSE) &&(send_msg!=NULL) )
				{
					void * flow_expand;
					ret=message_remove_expand(recv_msg,"FTRE",&flow_expand);
					if(flow_expand!=NULL) 
					{
						message_add_expand(send_msg,flow_expand);
					}
					else
					{
						set_message_head(send_msg,"receiver_uuid",msg_head->sender_uuid);
					}
				}
        			sec_subject_sendmsg(sub_proc,send_msg);
			}
		}
	}

	return 0;
}
#define MAX_RECORD_NUM 100

int proc_store_platform(void * sub_proc,void * message,void * pointer)
{
	MESSAGE_HEAD * message_head;
	struct platform_info * platform;
	int retval;
	int count=0;
	int i;

		// monitor send a new vm message
  	platform = NULL;
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
			FindPolicy(platform->uuid,"PLAI",&oldplatform);
			if(oldplatform!=NULL)
			{
				printf("this platform already in the PLAI lib!\n");
				continue;
			}
			oldplatform=GetFirstPolicy("PLAI");
			while(oldplatform!=NULL)
			{
				if(!strncmp(oldplatform->name,platform->name,DIGEST_SIZE*2))
				{
					strncpy(oldplatform->uuid,platform->uuid,DIGEST_SIZE*2);
					break;
				}
				oldplatform=GetNextPolicy("PLAI");
			}			
		}
		AddPolicy(platform,"PLAI");
	}
		// send a message to manager_trust
	retval=ExportPolicyToFile("./lib/PLAI.lib","PLAI");
		// send a message to manager_trust
	return count;
}

int proc_store_platform_policy(void * sub_proc,void * message,void * pointer)
{
	MESSAGE_HEAD * message_head;
	struct vm_policy * policy;
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
	printf("begin platform policy process!\n");

		// monitor send a new vm message
//	memset(vm,0,sizeof(struct vm_policy));
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
		if(oldpolicy!=NULL)
		{
			printf("this policy already in the PLAP lib!\n");
			continue;
		}
		AddPolicy(policy,"PLAP");
	}
		// send a message to manager_trust
	retval=ExportPolicyToFile("./lib/PLAP.lib","PLAP");
		// add the p

	return count;
}

int proc_send_platform_info(void * sub_proc,void * message,void ** new_msg)
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
	

	message_head=get_message_head(message);
	if(message_head==NULL)
		return -EINVAL;

		// monitor send a new vm message
//	memset(vm,0,sizeof(struct vm_policy));
  	platform = NULL;
	send_msg=message_create("PLAI");
	if(send_msg==NULL)
		return -EINVAL;
	platform=GetFirstPolicy("PLAI");
	while( platform != NULL)
	{
		message_add_record(send_msg,platform);
    		platform=GetNextPolicy("PLAI");
	}
	*new_msg=send_msg;

	
	return;
}

int proc_send_platform_policy(void * sub_proc,void * message,void ** new_msg)
{
	MESSAGE_HEAD * message_head;
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
	

	ret=message_get_record(message,&cmd,0);
	if(ret<0)
		return -EINVAL;

	

		// monitor send a new vm message
//	memset(vm,0,sizeof(struct vm_policy));
  	platform = NULL;
	send_msg=message_create("PLAP");
	if(send_msg==NULL)
		return -EINVAL;
	FindPolicy(cmd->uuid,"PLAP",&platform);
	message_add_record(send_msg,platform);
	*new_msg=send_msg;
	
	send_msg=message_create("PCRP");
	struct tcm_pcr_set * pcrpolicy;
	FindPolicy(platform->boot_pcr_uuid,"PCRP",&pcrpolicy);
	if(pcrpolicy!=NULL)
	{
		message_add_record(send_msg,pcrpolicy);
       		sec_subject_sendmsg(sub_proc,send_msg);
	}

	return;
}

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
}
/*
int process_monitor_vm(void * sub_proc,void * in, void * out)
{
	void * message;
	MESSAGE_HEAD * message_head;
	int record_size;
	BYTE * blob;
	int bloboffset;
	int record_num;
	int ret;
	char local_uuid[DIGEST_SIZE*2];
	struct tcloud_connector * policy_server_conn=(struct tcloud_connector *)server_conn;

	// send init message to 
	vm=GetFirstPolicy("VM_I");
	while( vm != NULL)
	{
		message=create_single_message_box(vm,"VM_I",local_uuid,local_uuid);
		if(message==NULL)
			return -EINVAL;
		if(IS_ERR(message))
			return -EINVAL;
		record_size=output_message_blob(message,&blob);
		ret=policy_server_conn->conn_ops->write(policy_server_conn,blob,record_size);
		if(ret<=0)
		{
			printf("send vm message error!");
		}
		else
		{
			printf("send vm %s 's message to policy server!\n",vm->uuid);
		}
		message_free(message);
		free(message);
    		vm=GetNextPolicy("VM_I");
	
	}
	
	monitor_vm_from_dbres(server_conn);
	return 0;
		
}
*/
