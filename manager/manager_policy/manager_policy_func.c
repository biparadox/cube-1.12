#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/extern_defno.h"
#include "../include/extern_struct.h"
#include "../include/sysfunc.h"
#include "../include/message_struct.h"
#include "../include/connector.h"
#include "../include/logic_baselib.h"
#include "../include/policy_ui.h"
#include "../include/vm_policy.h"
#include "../include/vmlist.h"
#include "../include/vtpm_struct.h"
#include "../include/sec_entity.h"
#include "../include/openstack_trust_lib.h"
#include "../include/main_proc_init.h"

#include "cloud_config.h"
#include "main_proc_func.h"
#include "proc_config.h"


struct main_proc_pointer
{
	void * pointer;
};
int manager_policy_init(void * proc,void * para)
{
	int ret;
	char local_uuid[DIGEST_SIZE*2];
	
	struct main_proc_pointer * main_pointer;
//	main_pointer= kmalloc(sizeof(struct main_proc_pointer),GFP_KERNEL);
	main_pointer= malloc(sizeof(struct main_proc_pointer));
	if(main_pointer==NULL)
		return -ENOMEM;
        ret=get_local_uuid(local_uuid);
        printf("this machine's local uuid is %s\n",local_uuid);
	proc_share_data_setvalue("uuid",local_uuid);
	proc_share_data_setvalue("proc_name",para);
	proc_share_data_setpointer(main_pointer);
	sec_subject_register_statelist(proc,main_state_list);
	return 0;
}

int vm_info_memdb_init(void * sub_proc,void * para)
{
	int retval;
	char * record_package;

	return 0;
}

int image_info_memdb_init(void * sub_proc,void * para)
{
	int retval;
	char * record_package;

	return 0;
}

int platform_info_memdb_init(void * sub_proc,void * para)
{
	int retval;
	char * record_package;

	return 0;
}

int vm_policy_memdb_init(void * sub_proc,void * para)
{
	int retval;
	char * record_package;

	return 0;
}
int image_policy_memdb_init(void * sub_proc,void * para)
{
	int retval;
	char * record_package;

	return 0;
}
int platform_policy_memdb_init(void * sub_proc,void * para)
{
	int retval;
	char * record_package;

	return 0;
}


int pcr_policy_memdb_init()
{
	int retval;
	char * record_package;

	return 0;
}

int policy_file_memdb_init()
{
	int retval;
	char * record_package;

	return 0;
}

int process_monitor_vm(void * message_box)
{
	MESSAGE_HEAD * message_head;
	struct vm_info * vm;
	int retval;
	int count=0;

		// monitor send a new vm message
//	vm=malloc(sizeof(struct vm_info));
//	if(vm==NULL)
//		return -ENOMEM;
	memset(vm,0,sizeof(struct vm_info));
	while((retval=message_get_record(message_box,&vm,count))>0)
	{
		void * oldvm;
		printf("policy server receive vm  %s's info from monitor!\n",vm->uuid);
		oldvm=FindPolicy(vm->uuid,"VM_I");
		if(oldvm!=NULL)
		{
			printf("this vm already in the VM_I lib!\n");
			continue;
		}
		AddPolicy(vm,"VM_I");
		count++;
	}while(retval>0);
		// send a message to manager_trust
	retval=ExportPolicyToFile("./lib/VM_I.lib","VM_I");
		// send a message to manager_trust
	return count;
}

int process_monitor_image(void * message_box)
{
	MESSAGE_HEAD * message_head;
	struct image_info * image;
	int retval;
	int count=0;

		// monitor send a new vm message
//	image=malloc(sizeof(struct image_info));
//	if(image==NULL)
//		return -ENOMEM;
//	memset(image,0,sizeof(struct image_info));
	while((retval=message_get_record(message_box,&image,count))>0)
	{
		void * oldimage;
		printf("policy server receive image  %s's info from monitor!\n",image->uuid);
		oldimage=FindPolicy(image->uuid,"IMGI");
		if(oldimage!=NULL)
		{
			printf("this image already in the IMAGE lib!\n");
			continue;
		}
		AddPolicy(image,"IMGI");
		count++;
	}while(retval>0);
	retval=ExportPolicyToFile("./lib/IMGI.lib","IMGI");
		// send a message to manager_trust
	return count;
}

int process_monitor_platform(void * message_box)
{
	MESSAGE_HEAD * message_head;
	struct platform_info * platform;
	int retval;

		// monitor send a new vm message
//	platform=malloc(sizeof(struct platform_info));
//	if(platform==NULL)
//		return -ENOMEM;
	memset(platform,0,sizeof(struct platform_info));
	retval=message_get_record(message_box,&platform,0);
	printf("policy server receive vm  %s's info from monitor!\n",platform->uuid);
	retval=AddPolicy(platform,"PLAI");
	retval=ExportPolicyToFile("./lib/PLAI.lib","PLAI");
		// send a message to manager_trust
	return retval;
}

int process_monitor_imagepolicy(void * message_box)
{
	MESSAGE_HEAD * message_head;
	struct vm_policy * image_policy;
	int retval;

		// monitor send a new vm message
//	image_policy=malloc(sizeof(struct vm_policy));
//	if(image_policy==NULL)
//		return -ENOMEM;
	memset(image_policy,0,sizeof(struct vm_policy));
	retval=message_get_record(message_box,&image_policy,0);
	printf("policy server receive image  %s's policy from monitor!\n",image_policy->uuid);
	retval=AddPolicy(image_policy,"VM_P");
	retval=ExportPolicy("VM_P");
		// send a message to manager_trust
	return retval;
}

/*
int send_vm_list(void * cmd,void * conn)
{
	struct request_cmd * req_cmd=cmd;
	struct message_box * message_box;
	struct vm_info * vm;
	char writebuf[1024];
	MESSAGE_HEAD * message_head;
	void * cmd_template;
	int retval;
	struct tcloud_connector * channel_conn=conn;

	if(strncmp(req_cmd->tag,"VM_I",4)!=0)
		return -EINVAL;
		
	// monitor send a new image message
	
	message_box=create_empty_message("VM_I",local_uuid,"manager_interface",0);

	vm=GetFirstPolicy("VM_I");
	while(vm!=NULL)
	{
		add_record_to_message(message_box,vm);
		vm=GetNextPolicy("VM_I");
	}

	retval=message_send(message_box,conn);
	if(retval>0)
	{
		printf("send %d vm info data to client!\n",retval);
	}
	message_free(message_box);
	return 0;
}

int send_image_list(void * cmd,void * conn)
{
	struct request_cmd * req_cmd=cmd;
	struct message_box * message_box;
	struct image_info * image;
	char writebuf[1024];
	MESSAGE_HEAD * message_head;
	void * cmd_template;
	BYTE * blob;
	int record_size;
	int retval;
	struct tcloud_connector * channel_conn=conn;

	if(strncmp(req_cmd->tag,"IMGI",4)!=0)
		return -EINVAL;
		
	// monitor send a new image message
	
	message_box=create_empty_message("IMGI",local_uuid,"manager_interface",0);

	image=GetFirstPolicy("IMGI");
	while(image!=NULL)
	{
		add_record_to_message(message_box,image);
		image=GetNextPolicy("IMGI");
	}

	retval=message_send(message_box,conn);
	if(retval>0)
	{
		printf("send %d image info data to client!\n",retval);
	}
	message_free(message_box);
	return 0;
}

int send_platform_list(void * cmd,void * conn)
{
	return 0;
}

int verify_image(char * uuid,void * conn,void * verifier)
{
	struct vm_policy * policy;
	void * message_box;
	void * image_verify_object;

	policy = FindPolicy(uuid,"VM_P");
	if(policy==NULL)
		return -EINVAL;
	if(policy->trust_level!=0)
	{
		message_box=create_empty_message("VM_P",local_uuid,"manager_interface",0);
		add_record_to_message(message_box,policy);
		message_send(message_box,conn);
		free(message_box);
		return 1;
	}

	image_verify_object=sec_object_init(uuid,NULL);
	if(image_verify_object==NULL)
		return -EINVAL;
	sec_object_setstate(image_verify_object,0);
	struct image_policy_object * pointer=malloc(sizeof(struct image_policy_object));
	memset(pointer,0,sizeof(struct image_policy_object));
	pointer->conn=conn;
	sec_object_setpointer(image_verify_object,pointer);
	pointer->image_policy=policy;
	if(pointer->image_policy==NULL)
		return -EINVAL;

	add_sec_object(image_verify_object);
	message_box=create_empty_message("VM_P",local_uuid,"manager_policy",0);
	add_record_to_message(message_box,policy);
	message_send(message_box,verifier);
	free(message_box);
	return 0;
}

int verify_vm(char * uuid,void * conn,void * trust_conn)
{
	struct vm_policy * policy;
	void * message_box;
	void * vm_verify_object;

	policy = FindPolicy(uuid,"VM_P");
	if(policy==NULL)
		return -EINVAL;
	if(policy->trust_level!=0)
	{
		message_box=create_empty_message("VM_P",local_uuid,"manager_interface",0);
		add_record_to_message(message_box,policy);
		message_send(message_box,conn);
		free(message_box);
		return 1;
	}

	vm_verify_object=sec_object_init(uuid,NULL);
	if(vm_verify_object==NULL)
		return -EINVAL;
	sec_object_setstate(vm_verify_object,0);
	struct vm_policy_object * pointer=malloc(sizeof(struct vm_policy_object));
	memset(pointer,0,sizeof(struct vm_policy_object));
	pointer->conn=conn;
	sec_object_setpointer(vm_verify_object,pointer);
	pointer->vm_policy=policy;
	if(pointer->vm_policy==NULL)
		return -EINVAL;

	add_sec_object(vm_verify_object);
	message_box=create_empty_message("VM_P",local_uuid,"compute_policy",0);
	add_record_to_message(message_box,policy);
	message_send(message_box,trust_conn);
	free(message_box);
	return 0;
}


int process_interface_cmd(void * message,void * conn,void * verifier,void * trust_conn)
{	
	struct request_cmd req_cmd;
	struct message_box * message_box=message;
	char writebuf[1024];
	MESSAGE_HEAD * message_head;
	void * syn_template;
	BYTE * blob;
	int record_size;
	int retval;
	struct tcloud_connector * channel_conn = conn;
	struct tcloud_connector * verifier_conn = verifier;


	memset(&req_cmd,0,sizeof(struct request_cmd));
	// get message's  head
	message_head=get_message_head(message_box);
	if(strncmp(message_head->record_type,"REQC",4)!=0)
		return -EINVAL;
		
	// monitor send a new image message
	retval=load_message_record(message_box,&req_cmd);

	if(retval<0)
		return -EINVAL;

	if(strncmp(req_cmd.tag,"VM_I",4)==0)
	{
		retval=send_vm_list(&req_cmd,channel_conn);
		return retval;
	}
	else if(strncmp(req_cmd.tag,"IMGI",4)==0)
	{
		printf("receive manager_interface's image info request!\n");
		retval=send_image_list(&req_cmd,channel_conn);
		return retval;
	}
	else if(strncmp(req_cmd.tag,"PLAI",4)==0)
	{
		retval=send_platform_list(&req_cmd,channel_conn);
		return retval;
	}
	else if(strncmp(req_cmd.tag,"SIGD",4)==0)
	{
		if(strncmp(req_cmd.etag,"IMGI",4)==0)
		{
			retval = verify_image(req_cmd.uuid,conn,verifier);
			return retval;
		}
		if(strncmp(req_cmd.etag,"VM_I",4)==0)
		{
			retval = verify_vm(req_cmd.uuid,conn,trust_conn);
			return retval;
		}
	}
	else
	{
		return -EINVAL;
	}

	message_free(message_box);

	return 0;

}

int process_verify_data(void * message)
{	
	struct verify_info verify_data;
	struct message_box * message_box=message;
	MESSAGE_HEAD * message_head;
	int retval;

	struct tcloud_connector * channel_conn;


	memset(&verify_data,0,sizeof(struct verify_info));
	// get message's  head
	message_head=get_message_head(message_box);
	if(strncmp(message_head->record_type,"VERI",4)!=0)
		return -EINVAL;
		


	// monitor send a new image message
	retval=load_message_record(message_box,&verify_data);

	if(retval<0)
		return -EINVAL;
	void * sec_object = find_sec_object(verify_data.verify_data_uuid);

	if(sec_object==NULL)
		return -EINVAL;
	struct image_policy_object * image_object=sec_object_getpointer(sec_object);
		
	retval=message_forward(message,image_object->conn);

	return retval;

}
*/
