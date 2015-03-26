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


int manager_vm_init(void * sub_proc,void * para)
{
	int ret;
	char local_uuid[DIGEST_SIZE*2];
	
	sec_subject_register_statelist(sub_proc,monitor_state_list);

	return 0;
}

int manager_vm_start(void * sub_proc,void * para)
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
	printf("begin vm manager process!\n");

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
		if(strncmp(msg_head->record_type,"VM_I",4)==0)
		{
			proc_store_vm(sub_proc,recv_msg,NULL);
		}
		if(strncmp(msg_head->record_type,"VM_P",4)==0)
		{
			proc_store_vm_policy(sub_proc,recv_msg,NULL);
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
			if(strncmp(req->tag,"VM_I",4)==0)
			{
				proc_send_vm_info(sub_proc,recv_msg,&send_msg);
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
					sec_subject_sendmsg(sub_proc,send_msg);
				}
			}
			else if(strncmp(req->tag,"VM_P",4)==0)
			{
				proc_send_vm_policy(sub_proc,recv_msg,&send_msg);
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
					sec_subject_sendmsg(sub_proc,send_msg);
				}
			}
		}
	}

	return 0;
}
#define MAX_RECORD_NUM 100

int proc_store_vm(void * sub_proc,void * message,void * pointer)
{
	MESSAGE_HEAD * message_head;
	struct vm_info * vm;
	int retval;
	int count=0;
	int i;
	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	retval=proc_share_data_getvalue("uuid",local_uuid);
	if(retval<0)
		return retval;
	retval=proc_share_data_getvalue("proc_name",proc_name);

	if(retval<0)
		return retval;

		// monitor send a new vm message
//	memset(vm,0,sizeof(struct vm_info));
  	vm = NULL;
	for(i=0;i<MAX_RECORD_NUM;i++)
	{
		retval=message_get_record(message,&vm,i);
		if(retval<0)
			break;
		if(vm==NULL)
			break;
		void * oldvm;
		printf("policy server receive vm  %s's info from monitor!\n",vm->uuid);
		FindPolicy(vm->uuid,"VM_I",&oldvm);
		if(oldvm!=NULL)
		{
			printf("this vm already in the VM_I lib!\n");
			continue;
		}
		AddPolicy(vm,"VM_I");
	}
		// send a message to manager_trust
	retval=ExportPolicyToFile("./lib/VM_I.lib","VM_I");
		// send a message to manager_trust
	return count;
}

int proc_store_vm_policy(void * sub_proc,void * message,void * pointer)
{
	MESSAGE_HEAD * message_head;
	struct vm_policy * vm;
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
	printf("begin vm policy process!\n");

		// monitor send a new vm message
//	memset(vm,0,sizeof(struct vm_policy));
  	vm = NULL;
	for(i=0;i<MAX_RECORD_NUM;i++)
	{
		retval=message_get_record(message,&vm,i);
		if(retval<0)
			break;
		if(vm==NULL)
			break;
		void * oldvm;
		printf("policy server receive vm  %s's info from monitor!\n",vm->uuid);
		FindPolicy(vm->uuid,"VM_P",&oldvm);
		if(oldvm!=NULL)
		{
			printf("this vm already in the VM_I lib!\n");
			continue;
		}
		AddPolicy(vm,"VM_P");
	}
		// send a message to manager_trust
	retval=ExportPolicyToFile("./lib/VM_P.lib","VM_P");
		// forward  message to verifier
	return count;
}

int proc_send_vm_info(void * sub_proc,void * message,void ** new_msg)
{
	MESSAGE_HEAD * message_head;
	struct vm_info * vm;
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
	printf("begin vm send image info process!\n");

	void * send_msg;
	

	message_head=get_message_head(message);
	if(message_head==NULL)
		return -EINVAL;

		// monitor send a new vm message
//	memset(vm,0,sizeof(struct vm_policy));
  	vm = NULL;
	send_msg=message_create("VM_I");
	if(send_msg==NULL)
		return -EINVAL;
	vm=GetFirstPolicy("VM_I");
	while( vm != NULL)
	{
		message_add_record(send_msg,vm);
    		vm=GetNextPolicy("VM_I");
	}
	*new_msg=send_msg;
	
	return;
}
int proc_send_vm_policy(void * sub_proc,void * message,void ** new_msg)
{
	MESSAGE_HEAD * message_head;
	struct vm_policy * vm;
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
	printf("begin send vm policy process!\n");

	void * send_msg;
	
	*new_msg=NULL;

	ret=message_get_record(message,&cmd,0);
	if(ret<0)
		return -EINVAL;

		// monitor send a new vm message
//	memset(vm,0,sizeof(struct vm_policy));
  	vm = NULL;
	FindPolicy(cmd->uuid,"VM_P",&vm);
	if(vm==NULL)
		return 0;
	send_msg=message_create("VM_P");
	if(send_msg==NULL)
		return -EINVAL;
	message_add_record(send_msg,vm);
	*new_msg=send_msg;
	
	send_msg=message_create("PCRP");
	struct tcm_pcr_set * pcrpolicy;
	FindPolicy(vm->boot_pcr_uuid,"PCRP",&pcrpolicy);
	if(pcrpolicy!=NULL)
	{
		message_add_record(send_msg,pcrpolicy);
       		sec_subject_sendmsg(sub_proc,send_msg);
	}
	return;
}

