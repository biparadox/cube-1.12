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
	struct vm_policy compute_policy;
};

int compute_monitor_init(void * proc,void * para)
{
	int ret;
	char local_uuid[DIGEST_SIZE*2];
	char hostname[DIGEST_SIZE*2];
	
	struct main_proc_pointer * main_pointer;
	system("mkdir mnt");
	main_pointer= malloc(sizeof(struct main_proc_pointer));
	if(main_pointer==NULL)
		return -ENOMEM;
	memset(main_pointer,0,sizeof(struct main_proc_pointer));
        ret=get_local_uuid(local_uuid);
        printf("this machine's local uuid is %s\n",local_uuid);
	ret=gethostname(hostname,DIGEST_SIZE*2);
	if(ret<0)
		return ret;
	proc_share_data_setvalue("uuid",local_uuid);
	proc_share_data_setvalue("host_name",hostname);
	proc_share_data_setvalue("proc_name",para);
	proc_share_data_setpointer(main_pointer);
	build_image_mount_respool(8,16,"image_mntpoint");

	return 0;
}
int image_policy_memdb_init()
{
	int retval;
	char *image_dirname="image";
	return 0;
}

#define MBR_PCR_INDEX  4
#define KERNEL_PCR_INDEX  10
#define SECURE_PCR_INDEX  11

int vm_policy_memdb_init()
{
	return 0;
}
int platform_policy_memdb_init()
{
	return 0;
}
int platform_info_memdb_init()
{
	int ret;
	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	char hostname[DIGEST_SIZE*2+1];
	struct platform_info * platform;
	ret=proc_share_data_getvalue("uuid",local_uuid);
	if(ret<0)
		return ret;
	ret=proc_share_data_getvalue("proc_name",proc_name);
	if(ret<0)
		return ret;
	ret=proc_share_data_getvalue("host_name",hostname);
	if(ret<0)
		return ret;

	platform = malloc(sizeof(struct platform_info));
	if(platform==NULL)
		return -ENOMEM;
	memset(platform,0,sizeof(struct platform_info));
	Memcpy(platform->uuid,local_uuid,DIGEST_SIZE*2);
	platform->name=dup_str(hostname,DIGEST_SIZE*2);

	AddPolicy(platform,"PLAI");
	ExportPolicy("PLAI");

	return 0;
}
int pcr_policy_memdb_init()
{
	int ret;
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

	struct vm_policy * compute_policy;
	struct tcm_pcr_set * compute_boot_pcrs;
	struct tcm_pcr_set * compute_running_pcrs;

	compute_boot_pcrs=NULL;
	build_compute_running_pcrs("/dev/sda",hostname,&compute_running_pcrs);

	ret=build_entity_policy(local_uuid,NULL,compute_boot_pcrs,compute_running_pcrs,hostname,&compute_policy);
	
	ExportPolicy("PCRP");	
	ExportPolicy("PLAP");	
	return 0;
}
int file_policy_memdb_init()
{
	return 0;
}
