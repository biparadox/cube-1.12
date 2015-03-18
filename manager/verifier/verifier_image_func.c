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
#include "verifier_image_func.h"
#include "local_func.h"

int verifier_image_init(void * sub_proc,void * para)
{
	int ret;
	char local_uuid[DIGEST_SIZE*2];
	
//	struct aik_proc_pointer * aik_pointer;
//	main_pointer= kmalloc(sizeof(struct main_proc_pointer),GFP_KERNEL);
	sec_subject_register_statelist(sub_proc,subproc_state_list);

	return 0;
}

int verifier_image_start(void * sub_proc,void * para)
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
		if(strncmp(msg_head->record_type,"IMGP",4)==0)
		{
			proc_verify_image(sub_proc,message_box,NULL);
		}
	}

	return 0;
}
#define MAX_RECORD_NUM 100

int proc_verify_image(void * sub_proc,void * message,void * pointer)
{
	MESSAGE_HEAD * message_head;
	struct vm_policy * policy;
	struct tcm_pcr_set * boot_pcrs;
	struct tcm_pcr_set * running_pcrs;
	void * sec_obj;

	int retval;
	int count=0;
	int i,j;
	struct verify_info ** verify_list;
	char buffer[1024];

	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	int ret;

	ret=proc_share_data_getvalue("uuid",local_uuid);
	if(ret<0)
		return ret;
	ret=proc_share_data_getvalue("proc_name",proc_name);

	if(ret<0)
		return ret;
	printf("begin image verify manager process!\n");
	message_head=get_message_head(message);
	if(message_head==NULL)
		return -EINVAL;
	int trust_level;

	policy=NULL;

	for(i=0;i<MAX_RECORD_NUM;i++)
	{
		retval=get_message_record(message,&policy,i);
		if(retval<0)
			break;
		if(policy==NULL)
			break;
		int waittime=10;
		for(j=0;j<waittime;j++)
		{
			sec_obj=find_sec_object(policy->boot_pcr_uuid);
			if(sec_obj!=NULL)
				break;
			usleep(time_val.tv_usec);
		}	
		if(sec_obj==NULL)
			return -EINVAL;
		boot_pcrs=sec_object_getpointer(sec_obj);
		if(boot_pcrs==NULL)
			return -EINVAL;
		for(j=0;j<2;j++)
		{
			sec_obj=find_sec_object(policy->runtime_pcr_uuid);
			if(sec_obj!=NULL)
				break;
			usleep(time_val.tv_usec);
		}
		if(sec_obj!=NULL)
			running_pcrs=sec_object_getpointer(sec_obj);
		else
			running_pcrs=NULL;

		verify_list=create_verify_list("IMGP",policy->uuid,10);
	
		retval=verify_pcrs_set(boot_pcrs,verify_list);
		if(running_pcrs!=NULL)
			retval=verify_pcrs_set(running_pcrs,verify_list);

		void * send_msg;
		send_msg=create_empty_message("VERI",proc_name,message_head->sender_uuid,MSG_FLAG_REMOTE);

		int curr_verify=0;
		while(verify_list[curr_verify]!=NULL)
		{
			if(verify_list[curr_verify]->verify_data_uuid[0]==0)
				break;
			add_record_to_message(send_msg,verify_list[curr_verify]);
			curr_verify++;
		}
		sec_subject_sendmsg(sub_proc,send_msg);
	}

	return 0;
}
