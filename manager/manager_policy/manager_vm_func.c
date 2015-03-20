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
	
//	struct aik_proc_pointer * aik_pointer;
//	main_pointer= kmalloc(sizeof(struct main_proc_pointer),GFP_KERNEL);
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

	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	
	ret=proc_share_data_getvalue("uuid",local_uuid);
	if(ret<0)
		return ret;
	ret=proc_share_data_getvalue("proc_name",proc_name);

	if(ret<0)
		return ret;
	printf("begin vm manager process!\n");

	for(i=0;i<300*1000;i++)
	{
		usleep(time_val.tv_usec);
		ret=sec_subject_recvmsg(sub_proc,&message_box);
		if(ret<0)
			continue;
		if(message_box==NULL)
			continue;
		MESSAGE_HEAD * msg_head;
		msg_head=get_message_head(message_box);
		if(msg_head==NULL)
			continue;
		if(strncmp(msg_head->record_type,"VM_I",4)==0)
		{
			proc_store_vm(sub_proc,message_box,NULL);
		}
		if(strncmp(msg_head->record_type,"VM_P",4)==0)
		{
			proc_store_vm_policy(sub_proc,message_box,NULL);
		}
		if(strncmp(msg_head->record_type,"REQC",4)==0)
		{
			struct request_cmd * req;
			ret=message_get_record(message_box,&req,0);
			if(ret<0)
			{
				printf("error request command!\n");
				continue;
			}
			if(strncmp(req->tag,"VM_I",4)==0)
			{
				proc_send_vm_info(sub_proc,message_box,NULL);
			}
			else if(strncmp(req->tag,"VM_P",4)==0)
			{
				proc_send_vmpolicy_req(sub_proc,message_box,req->uuid);
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
		oldvm=FindPolicy(vm->uuid,"VM_I");
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
		oldvm=FindPolicy(vm->uuid,"VM_P");
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

int proc_send_vm_info(void * sub_proc,void * message,void * pointer)
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
	sec_subject_sendmsg(sub_proc,send_msg);
	
	return;
}

int proc_send_vmpolicy_req(void * sub_proc,void * message,void * pointer)
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
	printf("begin to send vmpolicy request!\n");

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
    	memcpy(cmd->tag,"VM_P",4);
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
