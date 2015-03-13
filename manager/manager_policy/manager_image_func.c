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
	
//	struct aik_proc_pointer * aik_pointer;
//	main_pointer= kmalloc(sizeof(struct main_proc_pointer),GFP_KERNEL);
	sec_subject_register_statelist(sub_proc,monitor_state_list);

	return 0;
}

int manager_image_start(void * sub_proc,void * para)
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
	printf("begin image manager process!\n");

	for(i=0;i<3000*1000;i++)
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
		if(strncmp(msg_head->record_type,"IMGI",4)==0)
		{
			proc_store_image(sub_proc,message_box,NULL);
		}
		if(strncmp(msg_head->record_type,"IMGP",4)==0)
		{
			proc_store_image_policy(sub_proc,message_box,NULL);
		}
		if(strncmp(msg_head->record_type,"PCRP",4)==0)
		{
			proc_store_pcr_policy(sub_proc,message_box,NULL);
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
			if(strncmp(req->tag,"IMGI",4)==0)
			{
				proc_send_image_info(sub_proc,message_box,NULL);
			}
			else if(strncmp(req->tag,"IMGP",4)==0)
			{
				proc_send_imagepolicy_info(sub_proc,message_box,req->uuid);
			}
		}
	}

	return 0;
}
#define MAX_RECORD_NUM 100

int proc_store_image(void * sub_proc,void * message,void * pointer)
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
		oldimage=FindPolicy(image->uuid,"IMGI");
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

int proc_store_image_policy(void * sub_proc,void * message,void * pointer)
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
		oldimage=FindPolicy(image->uuid,"IMGP");
		if(oldimage!=NULL)
		{
			printf("this image's policy  already in the IMGP lib!\n");
			continue;
		}
		AddPolicy(image,"IMGP");
/*
		void * send_msg;
		send_msg=create_empty_message("IMGP",proc_name,message_head->sender_uuid,MSG_FLAG_REMOTE);
		if(send_msg==NULL)
			return -EINVAL;
		message_add_record(send_msg,image);
		sec_subject_sendmsg(sub_proc,send_msg);
		*/
	}
		// send a message to manager_trust
	retval=ExportPolicyToFile("./lib/IMGP.lib","IMGP");
		// forward  message to verifier
/*
	set_message_head(message,"sender_uuid",proc_name);
	set_message_head(message,"receiver_uuid","verifier");
	sec_subject_sendmsg(sub_proc,message);
	*/
	return count;
}

int proc_store_pcr_policy(void * sub_proc,void * message,void * pointer)
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
		oldpcrs=FindPolicy(pcrs->uuid,"PCRP");
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

int proc_send_image_info(void * sub_proc,void * message,void * pointer)
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
	send_msg=message_create("IMGI");
	if(send_msg==NULL)
		return -EINVAL;
	image=GetFirstPolicy("IMGI");
	while(image!=NULL)
	{
		message_add_record(send_msg,image);
		image=GetNextPolicy("IMGI");
	}
	sec_subject_sendmsg(sub_proc,send_msg);
	
	return;
}
int proc_send_imagepolicy_info(void * sub_proc,void * message,void * pointer)
{
	MESSAGE_HEAD * message_head;
	struct vm_policy * image_policy;
	struct tcm_pcr_set * pcrs;
	int retval;
	int ret;
	int count=0;
	int i;
	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	char * image_uuid=pointer;
	
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

		// monitor send a new vm message
//	memset(vm,0,sizeof(struct vm_policy));
  	image_policy = NULL;
	send_msg=message_create("IMGP");
	if(send_msg==NULL)
		return -EINVAL;
	send_pcr_msg=message_create("PCRP");
	if(send_pcr_msg==NULL)
		return -EINVAL;
	image_policy=FindPolicy(image_uuid,"IMGP");
	if( image_policy != NULL)
	{
		message_add_record(send_msg,image_policy);
		pcrs=FindPolicy(image_policy->boot_pcr_uuid,"PCRP");
		if(pcrs!=NULL)
			message_add_record(send_pcr_msg,pcrs);
		pcrs=FindPolicy(image_policy->runtime_pcr_uuid,"PCRP");
		if(pcrs!=NULL)
			message_add_record(send_pcr_msg,pcrs);

		sec_subject_sendmsg(sub_proc,send_pcr_msg);
		usleep(time_val.tv_usec);
		sec_subject_sendmsg(sub_proc,send_msg);
	}
	else
	{
		printf("can't find the image %s's policy!\n",image_uuid);

	}
	
	return;
}
/*
	for(i=0;i<MAX_RECORD_NUM;i++)
	{
		retval=message_get_record(message,&image,i);
		if(retval<0)
			break;
		if(image==NULL)
			break;
		void * oldimage;
		printf("policy server receive imagevm  %s's info from monitor!\n",vm->uuid);
		oldvm=FindPolicy(vm->uuid,"VM_P");
		if(oldvm!=NULL)
		{
			printf("this vm already in the VM_I lib!\n");
			continue;
		}
		AddPolicy(vm,"VM_P");
	}
		// send a message to manager_trust
	retval=ExportPolicyToFile("./lib/VM_I.lib","VM_P");
*/
/*
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
	retval=ExportPolicyToFile("./lib/VM_I.lib","VM_P");
		// forward  message to verifier
	set_message_head(message,"sender_uuid",proc_name);
	set_message_head(message,"receiver_uuid","verifier");
	sec_subject_sendmsg(sub_proc,message);
	return count;
}
*/



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
