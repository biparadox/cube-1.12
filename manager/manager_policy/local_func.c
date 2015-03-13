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

#include "local_func.h"

#define MBR_PCR_INDEX  4
#define KERNEL_PCR_INDEX  10
#define SECURE_PCR_INDEX  11

void * build_glance_image_policy(char * uuid)

{
	char cmd[512];
	char desc[512];
	char namebuf[512];
	char digest[DIGEST_SIZE];
	struct policy_file * pfile;
	struct tcm_pcr_set * pcrs;
	struct vm_policy * image_policy;
	void * struct_template;

	char * image_path="/var/lib/glance/images/";	
	sprintf(namebuf,"%s%s",image_path,uuid);

	image_policy=malloc(sizeof(struct vm_policy));
	if(image_policy==NULL)
		return NULL;

	memset(image_policy,0,sizeof(struct vm_policy));
	strncpy(image_policy->uuid,uuid,DIGEST_SIZE*2);

	sprintf(cmd,"qemu-nbd -c /dev/nbd1 %s",namebuf);
        system(cmd);
        system("mount -o ro /dev/nbd1p1 ./mnt");
        system("dd if=/dev/nbd1p1 of=temp.txt count=1 bs=512");
        calculate_sm3("temp.txt",digest);
        system("rm temp.txt");

	// build this image's MBR policy  
	pcrs=build_empty_pcr_set();
	add_pcr_to_set(pcrs,MBR_PCR_INDEX,digest);
	sprintf(desc,"image %s's MBR digest",uuid);
	pcrs->policy_describe=dup_str(desc,0);

	memcpy(image_policy->boot_pcr_uuid,pcrs->uuid,DIGEST_SIZE*2);

	// add kernel and initimage's digest to pcr_set
	char *file_arg[20];
	FILE * fp;
	char kernelname[256];
	char initrdname[256];
	int  retval;
	fp=fopen("./mnt/boot/grub/menu.lst","r");
	if(fp==NULL)
		return -EINVAL;
	file_arg[0]=malloc(1024);
	if(file_arg[0]==NULL)
		return -ENOMEM;
	
	do {
		retval=read_arg(fp,file_arg);
		if(retval<0)
			break;
		if(retval==0)
			continue;
		if(strcmp(file_arg[0],"kernel")!=0)
			continue;
		strncpy(kernelname,file_arg[1],256);
		retval=read_arg(fp,file_arg);
		if(retval<0)
			break;
		if(retval==0)
			continue;
		if(strcmp(file_arg[0],"initrd")!=0)
			continue;
		strncpy(initrdname,file_arg[1],256);
		pcrs=build_empty_pcr_set();
		printf("Please input the description of grub:");
//		scanf("%s",desc);
//		sprintf(desc,"kernel %s and initrd %s 's digest",kernelname,initrdname);
		pcrs->policy_describe=dup_str(desc,0);
		sprintf(namebuf,"./mnt/%s",kernelname);
		calculate_sm3(namebuf,digest);
		add_pcr_to_set(pcrs,KERNEL_PCR_INDEX,digest);
		sprintf(namebuf,"./mnt/%s",initrdname);
		calculate_sm3(namebuf,digest);
		add_pcr_to_set(pcrs,KERNEL_PCR_INDEX,digest);
		break;
	}while(1);

	memcpy(image_policy->runtime_pcr_uuid,pcrs->uuid,DIGEST_SIZE*2);

	//      Generate secure module

        system("umount ./mnt -l");
	sleep(1);
        system("qemu-nbd -d /dev/nbd1");
	AddPolicy(image_policy,"VM_P");
	ExportPolicy("VM_P");
	return image_policy;
}

int proc_send_reqcmd(void * sub_proc,char * receiver,void * para)
{
	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	char * cmd_type=para;
	int  ret;
	
	ret=proc_share_data_getvalue("uuid",local_uuid);
	if(ret<0)
		return ret;
	ret=proc_share_data_getvalue("proc_name",proc_name);

	if(ret<0)
		return ret;
	printf("begin send %s reqcmd!\n",cmd_type);
    	void * send_msg;
    	send_msg=create_empty_message("REQC",proc_name,receiver,MSG_FLAG_REMOTE);
    	struct request_cmd * cmd;
    	cmd=(struct request_cmd *)malloc(sizeof(struct request_cmd));
   	if(cmd==NULL)
   	memset(cmd,0,sizeof(struct request_cmd));
    	memcpy(cmd->tag,para,4);
        ret=add_record_to_message(send_msg,cmd);
        sec_subject_sendmsg(sub_proc,send_msg);
	return 0;
}


