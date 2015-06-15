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
#include "monitor_process_func.h"
#include "local_func.h"


int monitor_process_init(void * sub_proc,void * para)
{
	int ret;
	char local_uuid[DIGEST_SIZE*2];

	return 0;
}

int monitor_process_start(void * sub_proc,void * para)
{
	int ret;
	int retval;
	void * message_box;
	void * context;
	void * recv_msg;
	struct tcloud_connector * temp_conn;
	int i;

	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	char hostname[DIGEST_SIZE*2+1];
	ret=proc_share_data_getvalue("uuid",local_uuid);
	if(ret<0)
		return ret;
	ret=proc_share_data_getvalue("proc_name",proc_name);
	if(ret<0)
		return ret;
	ret=proc_share_data_getvalue("host_name",hostname);
	if(ret<0)
		return ret;

	printf("begin compute monitor process!\n");
	sleep(2);
	proc_send_compute_localinfo(sub_proc,NULL);

	for(i=0;i<3000*1000;i++)
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
			proc_send_compute_localinfo(sub_proc,recv_msg);
		}
		if(strncmp(msg_head->record_type,"VM_I",4)==0)
		{
			proc_compute_vmpolicy(sub_proc,recv_msg,NULL);
		}
		if(strncmp(msg_head->record_type,"REQC",4)==0)
		{

			struct request_cmd * cmd;
			ret=message_get_record(recv_msg,&cmd,0);
			if(strncmp(cmd->tag,"VM_P",4)==0)
			{
				proc_send_vmpolicy(sub_proc,recv_msg);
			}
			else if(strncmp(cmd->tag,"PLAP",4)==0)
			{
				proc_send_computepolicy(sub_proc,recv_msg);
			}
			else
				continue;
				
		}
	}

	return 0;
}
#define MAX_RECORD_NUM 100

int proc_compute_vmpolicy(void * sub_proc,void * message)
{
	MESSAGE_HEAD * message_head;
	struct vm_policy * policy;
	struct vm_info * vm;
	int retval;
	int count=0;
	int i,j;
	int ret;

	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	ret=proc_share_data_getvalue("uuid",local_uuid);
	if(ret<0)
		return ret;
	ret=proc_share_data_getvalue("proc_name",proc_name);
	if(ret<0)
		return ret;

	for(i=0;i<MAX_RECORD_NUM;i++)
	{
		retval=message_get_record(message,&vm,i);
		if(retval<0)
			break;
		if(vm==NULL)
			break;
		struct tcm_pcr_set * boot_pcrs;
		struct tcm_pcr_set * running_pcrs;
		ret=build_nova_vm_policy(vm->uuid,&boot_pcrs, &running_pcrs,&policy);
		ExportPolicy("PCRP");	
		ExportPolicy("VM_P");	
	}

	return;

}

int proc_send_vmpolicy(void * sub_proc,void * message)
{
	MESSAGE_HEAD * message_head;
	struct request_cmd * cmd;
	struct vm_policy * policy;
	int retval;
	int count=0;
	int i,j;
	int ret;

	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];

	printf("begin to send vmpolicy!\n");

	ret=proc_share_data_getvalue("uuid",local_uuid);
	if(ret<0)
		return ret;
	ret=proc_share_data_getvalue("proc_name",proc_name);
	if(ret<0)
		return ret;

	message_head=get_message_head(message);

	// get  vm info from message
	retval=message_get_record(message,&cmd,0);
	if(retval<0)
		return -EINVAL;

	struct tcm_pcr_set * boot_pcrs;
	struct tcm_pcr_set * running_pcrs;
	ret=build_nova_vm_policy(cmd->uuid,&boot_pcrs, &running_pcrs,&policy);
	if(policy==NULL)
		return -EEXIST;
	ExportPolicy("VM_P");	
	
	void * send_pcr_msg;
	void * send_msg;
	// send compute node's pcr policy
	send_pcr_msg=message_create("PCRP",NULL);
	message_add_record(send_pcr_msg,boot_pcrs);
	if(running_pcrs!=NULL)
		message_add_record(send_pcr_msg,running_pcrs);
		
	sec_subject_sendmsg(sub_proc,send_pcr_msg);
	usleep(time_val.tv_usec*3);

	send_msg=message_create("VM_P",message);
	message_add_record(send_msg,policy);
	sec_subject_sendmsg(sub_proc,send_msg);
	return 0;
}

int proc_send_computepolicy(void * sub_proc,void * message)
{
	MESSAGE_HEAD * message_head;
	struct request_cmd * cmd;
	int retval;
	int count=0;
	int i,j;
	int ret;

	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	char hostname[DIGEST_SIZE*2+1];

	printf("begin to send computepolicy!\n");

	ret=proc_share_data_getvalue("uuid",local_uuid);
	if(ret<0)
		return ret;
	ret=proc_share_data_getvalue("proc_name",proc_name);
	if(ret<0)
		return ret;
	ret=proc_share_data_getvalue("host_name",hostname);
	if(ret<0)
		return ret;

	struct vm_policy * compute_policy;
	struct tcm_pcr_set * compute_boot_pcrs;
	struct tcm_pcr_set * compute_running_pcrs;

	build_compute_boot_pcrs("/dev/sda",hostname,&compute_boot_pcrs);
	build_compute_running_pcrs("/dev/sda",hostname,&compute_running_pcrs);

	ret=build_entity_policy(local_uuid,NULL,compute_boot_pcrs,compute_running_pcrs,hostname,&compute_policy);
	if(compute_policy==NULL)
		return -EINVAL;
	ExportPolicy("PLAP");	

	void * send_pcr_msg;
	void * send_msg;
	// send compute node's pcr policy
	send_pcr_msg=message_create("PCRP",NULL);
	message_add_record(send_pcr_msg,compute_boot_pcrs);
	if(compute_running_pcrs!=NULL)
		message_add_record(send_pcr_msg,compute_running_pcrs);
		
	sec_subject_sendmsg(sub_proc,send_pcr_msg);

	
	usleep(time_val.tv_usec*3);
	// send compute node's  platform policy
	send_msg=message_create("PLAP",message);
	message_add_record(send_msg,compute_policy);
	sec_subject_sendmsg(sub_proc,send_msg);

	return 0;
}
