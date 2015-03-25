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
		FindPolicy(vm->uuid,"VM_I",&oldvm);
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
		FindPolicy(image->uuid,"IMGI",&oldimage);
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
