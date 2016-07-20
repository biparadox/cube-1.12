#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/extern_defno.h"
#include "../include/extern_struct.h"
#include "../include/message_struct.h"
#include "../include/connector.h"
#include "../include/logic_baselib.h"
#include "../include/policy_ui.h"
#include "../include/vm_policy.h"
#include "../include/vmlist.h"
#include "../include/vtpm_struct.h"
#include "../include/tesi.h"
#include "../include/openstack_trust_lib.h"
#include "../include/sec_entity.h"
//#include "./verifier_func.h"
#include "readconfig.h"

#include "cloud_config.h"
#include "local_func.h"
#include "cloud_policy.h"


#define MBR_PCR_INDEX  4
#define KERNEL_PCR_INDEX  10
#define SECURE_PCR_INDEX  11
#define VMM_PCR_INDEX  12
#define TRUSTBUS_PCR_INDEX  13
#define EXPAND_PCR_INDEX  23

	//      Generate secure module
/*
	pcrs=build_empty_pcr_set();
	sprintf(desc,"secure os for image %s",image_desc);
	pcrs->policy_describe=dup_str(desc,0);
	sprintf(namebuf,"./mnt/boot/os_safe.d/os_sec.ko");
	calculate_sm3(namebuf,digest);
	add_pcr_to_set(pcrs,KERNEL_PCR_INDEX,digest);
	AddPolicy(pcrs,"PCRP");

	system("ln -s ./mnt/boot/os_safe.d/whitelist whitelist");
	pfile=build_policy_file("verifier","DIGL",NULL,"whitelist");
	system("rm whitelist");
	AddPolicy(pfile,"FILP");
*/

struct image_mount_res
{
	int nbd_no;
	char mount_path[DIGEST_SIZE*2];
	char dev_name[DIGEST_SIZE*2];
}__attribute__((packed));
static struct struct_elem_attr image_mount_res_desc[]=
{
	{"nbd_no",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{"mount_path",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"dev_name",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};



int main(int argc,char ** argv)
{
	char cmd[512];
	int retval;
	char local_uuid [DIGEST_SIZE*2];
	char * proc_name = "policy_gen";
	char hostname [DIGEST_SIZE*2];
	struct verify_info ** verify_list;
	if(argc!=2)
	{
		printf("Error! correct usage: %s <trust_image_list> ",argv[0]);
		return - EINVAL;
	}
	char *file_arg[MAX_ARG_NUM];
	FILE * fp;
	void * pcrs;

	int i;
	retval=get_local_uuid(local_uuid);
	printf("this machine's local uuid is %s\n",local_uuid);
	retval=gethostname(hostname,DIGEST_SIZE*2);
	
	openstack_trust_lib_init();
	sec_respool_list_init();

	build_image_mount_respool(0,16,"image_mntpoint");
	
	register_lib("VM_P");
	register_lib("PCRP");
	register_lib("FILP");
	LoadPolicy("VM_P");
	LoadPolicy("PCRP");
	LoadPolicy("FILP");
	sprintf(cmd,"modprobe nbd");
        system(cmd);

	retval=build_compute_pcrlib("/dev/sda",
		"Host MBR:ubuntu 12.04 with boot loader grub2",2);
			

	struct vm_policy * compute_policy;
	struct tcm_pcr_set * compute_boot_pcrs;
	struct tcm_pcr_set * compute_running_pcrs;

	retval=build_compute_boot_pcrs("/dev/sda",hostname,&compute_boot_pcrs);
	retval=build_compute_running_pcrs("/dev/sda",hostname,&compute_running_pcrs);

	retval=build_entity_policy(local_uuid,NULL,compute_boot_pcrs,compute_running_pcrs,hostname,&compute_policy);
	verify_list=create_verify_list("PLAP",local_uuid,10);
	
	retval=verify_pcrs_set(compute_boot_pcrs,verify_list);
	retval=verify_pcrs_set(compute_running_pcrs,verify_list);

	printf("check compute result!\n");
	for(i=0;verify_list[i]!=NULL;i++)
	{
		if(verify_list[i]->verify_data_uuid[i]==0)
			continue;
		printf ("%s  trust level: %d uuid: %.64s\n",verify_list[i]->info,verify_list[i]->trust_level,verify_list[i]->verify_data_uuid);
	}

	fp=fopen(argv[1],"r");
	if(fp==NULL)
		return -EINVAL;
	file_arg[0]=malloc(MAX_LINE_LEN);
	if(file_arg[0]==NULL)
		return -ENOMEM;

	 int devno=15;	
	do {
		retval=read_arg(fp,file_arg);
		if(retval<0)
			break;
		if(retval==0)
			continue;
		int trust_level=atoi(file_arg[2]);
		if(trust_level<0)
			return -EINVAL;
		if(trust_level>4)
			return -EINVAL;

		
		build_glance_image_pcrlib(file_arg[0],file_arg[1],trust_level);

		struct vm_policy * image_policy;
		struct tcm_pcr_set * image_boot_pcrs;
		struct tcm_pcr_set * image_running_pcrs;
		

		retval=build_glance_image_policy(file_arg[0],&image_boot_pcrs,&image_running_pcrs,&image_policy);

		verify_list=create_verify_list("IMGP",local_uuid,10);
	
		retval=verify_pcrs_set(image_boot_pcrs,verify_list);
		retval=verify_pcrs_set(image_running_pcrs,verify_list);

		printf("check image %s 's result!\n",file_arg[0]);
		for(i=0;verify_list[i]!=NULL;i++)
		{
			if(verify_list[i]->verify_data_uuid[i]==0)
				continue;
			printf ("%s  trust level: %d uuid: %.64s\n",verify_list[i]->info,verify_list[i]->trust_level,verify_list[i]->verify_data_uuid);
		}
		sleep(3);
	}while(1);

		
	char * vm_uuid[]= {
		"d8a8c74e-eea6-45de-ae43-8600bb3d2656",
		NULL
	};

	for(i=0;vm_uuid[i]!=NULL;i++)
	{
		struct vm_policy * vm_policy;
		struct tcm_pcr_set * vm_boot_pcrs;
		struct tcm_pcr_set * vm_running_pcrs;
		retval=build_nova_vm_policy(vm_uuid[i],&vm_boot_pcrs,&vm_running_pcrs,&vm_policy);
		verify_list=create_verify_list("VM_P",local_uuid,10);
		retval=verify_pcrs_set(vm_boot_pcrs,verify_list);
		retval=verify_pcrs_set(vm_running_pcrs,verify_list);

		printf("check vm %s 's result!\n",vm_uuid[i]);
		int j;
		for(j=0;verify_list[j]!=NULL;j++)
		{
			if(verify_list[j]->verify_data_uuid[j]==0)
				continue;
			printf ("%s  trust level: %d uuid: %.64s\n",verify_list[j]->info,verify_list[j]->trust_level,verify_list[j]->verify_data_uuid);
		}
	}
	
	return 0;
}
		
