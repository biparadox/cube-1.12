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

#include "readconfig.h"
#include "cloud_policy.h"

#define MBR_PCR_INDEX  4
#define KERNEL_PCR_INDEX  10
#define SECURE_PCR_INDEX  11
#define VMM_PCR_INDEX  12
#define TRUSTBUS_PCR_INDEX  13
#define EXPAND_PCR_INDEX  23

static char * boot_file_list[] =
{
	"/boot/grub/menu.lst",
	"/boot/vmlinuz-3.5.0-18-generic",
	"/boot/initrd.img-3.5.0-18-generic",
	NULL
};
static char * trustbus_file_list[] =
{
	"/root/cube-1.1/proc/compute/compute_monitor/compute_monitor",
	"/root/cube-1.1/proc/compute/compute_monitor/main_proc_policy.cfg",
	NULL
};
static char * kvm_file_list[] =
{
//	"/etc/kvm/kvm-ifup",
//	"/etc/kvm/kvm-ifdown",
	"/usr/bin/qemu-system-x86_64",
	"/usr/bin/nova-compute",
	NULL
};
static char * os_sec_file_list[] =
{
	"/boot/os_safe.d/os_sec.ko",
	"/boot/os_safe.d/whitelist",
	NULL
};

struct  pcr_index_filelist
{
	int pcr_index;
	char * tail_desc;
	char ** filelist;
	int trust_level
} ;


static struct pcr_index_filelist compute_pcr_filelist[] =
{
	{KERNEL_PCR_INDEX,":kernel and initrd",boot_file_list,2},
	{TRUSTBUS_PCR_INDEX,":trustbus cube-1.0",trustbus_file_list,2},
	{VMM_PCR_INDEX,":kvm with qemu",kvm_file_list,2},
	{0,NULL}
};
static struct pcr_index_filelist image_pcr_filelist[] =
{
	{SECURE_PCR_INDEX,":os_sec and its whitelist",os_sec_file_list,1},
	{0,NULL}
};
static struct pcr_index_filelist vm_pcr_filelist[] =
{
	{SECURE_PCR_INDEX,":os_sec and its whitelist",os_sec_file_list,1},
	{0,NULL}
};


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

int build_image_mount_respool(int start_no,int end_no,char * name)
{
	void * sec_respool;
	void * sec_res;
	struct image_mount_res *  mnt_res;
	int i;	
	

	sec_respool=sec_respool_init(name);
	if(sec_respool==NULL)
		return -EINVAL;
	add_sec_respool(sec_respool);
	for(i=start_no;i<end_no;i++)
	{
		sec_res=sec_resource_init(name,&image_mount_res_desc);
		char buffer[DIGEST_SIZE*2+1];
		sec_resource_setvalue(sec_res,"nbd_no",&i);
		sprintf(buffer,"/dev/nbd%d",i);
		sec_resource_setvalue(sec_res,"dev_name",buffer);
		sprintf(buffer,"./mnt%d",i);
		sec_resource_setvalue(sec_res,"mount_path",buffer);
		sec_respool_addres(sec_respool,sec_res);
	}
	return 0;

}


void * build_MBR_pcrpolicy(char *dev,char * describe_info)
{
	struct tcm_pcr_set * pcrs;
	char namebuf[512];
	char cmd[512];
	char digest[DIGEST_SIZE];
	int ret;
	int i;
	
	pcrs=build_empty_pcr_set();
	if(pcrs==NULL)
		return NULL;
//	sprintf(cmd,"dd if=%s of=temp.txt count=61 bs=512 skip=3",dev);
	sprintf(cmd,"dd if=%s of=temp.txt count=64 bs=512",dev);
	system(cmd);
	calculate_sm3("temp.txt",digest);
	system("rm temp.txt");
	add_pcr_to_set(pcrs,MBR_PCR_INDEX,digest);
	sprintf(namebuf,"%s : MBR digest",describe_info);
	pcrs->policy_describe=dup_str(namebuf,0);
	return pcrs;
}

void * build_filelist_policy(char * mountpoint,char ** filelist,
	int pcr_index,char * describe_info)
{
	struct tcm_pcr_set * pcrs;
	char namebuf[512];
	char digest[DIGEST_SIZE];
	int ret;
	int i;

	pcrs=build_empty_pcr_set();
	if(pcrs==NULL)
		return NULL;
	if((pcr_index<0) || (pcr_index>24))
		return NULL;
	
	for(i=0;filelist[i]!=NULL;i++)
	{
		if(mountpoint!=NULL)
		{
			sprintf(namebuf,"%s/%s",mountpoint,filelist[i]);
			ret=calculate_sm3(namebuf,digest);
		}
		else
		{
			ret=calculate_sm3(filelist[i],digest);
		}
		if(ret<0)
			return NULL;
		usleep(10);
		add_pcr_to_set(pcrs,pcr_index,digest);
	}
	pcrs->policy_describe=dup_str(describe_info,0);
	return pcrs;
}

int add_filelist_policy(char * mountpoint,char ** filelist,
	int pcr_index,void * origin_pcrs)
{
	struct tcm_pcr_set * pcrs=origin_pcrs;
	char namebuf[512];
	char digest[DIGEST_SIZE];
	int ret;
	int i;

	if(pcrs==NULL)
		return -EINVAL;
	if((pcr_index<0) || (pcr_index>24))
		return -EINVAL;
	
	for(i=0;filelist[i]!=NULL;i++)
	{
		if(mountpoint!=NULL)
		{
			sprintf(namebuf,"%s/%s",mountpoint,filelist[i]);
			ret=calculate_sm3(namebuf,digest);
		}
		else
		{
			ret=calculate_sm3(filelist[i],digest);
		}
		if(ret<0)
		{
			memset(digest,0,sizeof(DIGEST_SIZE));
		}
		usleep(10);
		add_pcr_to_set(pcrs,pcr_index,digest);
	}
	return 0;
}

int build_compute_pcrlib(char * dev,char * compute_desc,int trust_level)
{
	char digest[DIGEST_SIZE];
	struct tcm_pcr_set * pcrs;
	struct tcm_pcr_set * boot_pcrs;
	char desc[512];
	int i;
	int ret;

	// build this image's MBR policy  
	boot_pcrs=build_MBR_pcrpolicy(dev,compute_desc);
	if(boot_pcrs!=NULL)
	{
		boot_pcrs->trust_level=trust_level;
		AddPolicy(boot_pcrs,"PCRP");
	}

	for(i=0;compute_pcr_filelist[i].filelist!=NULL;i++)
	{
		sprintf(desc,"%s %s",compute_desc,compute_pcr_filelist[i].tail_desc);
		pcrs=build_filelist_policy(NULL,compute_pcr_filelist[i].filelist,
			compute_pcr_filelist[i].pcr_index,desc);
		if(pcrs!=NULL)
		{
			pcrs->trust_level=trust_level;
			AddPolicy(pcrs,"PCRP");
		}
	}

	ExportPolicy("PCRP");
	return 0;
}

int build_image_kernelpcr(char * mountpoint,char * image_desc,int trust_level)
{
	char *boot_file_list[]={
		"/boot/grub/grub.conf",
		"/boot/grub/menu.lst",
		NULL
	};
	FILE * fp;
	char *file_arg[MAX_ARG_NUM];
	char filename[512];
	char kernelname[256];
	char initrdname[256];
	int  retval;
	int i;
	struct tcm_pcr_set * pcrs;
	char digest[DIGEST_SIZE];
	char desc[512];

	for(i=0;boot_file_list[i]!=NULL;i++)
	{
		sprintf(filename,"%s/%s",mountpoint,boot_file_list[i]);
		fp=fopen(filename,"r");
		if(fp!=NULL)
			break;
	}
	if(boot_file_list[i]==NULL)
	{
		printf("can't find image %s's boot file\n ",image_desc);
		return -EINVAL;
	}

	file_arg[0]=malloc(MAX_LINE_LEN);
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
		sprintf(desc,"image %s 's kernel digest",image_desc);
		pcrs->policy_describe=dup_str(desc,0);
		sprintf(filename,"%s/%s",mountpoint,kernelname);
		calculate_sm3(filename,digest);
		add_pcr_to_set(pcrs,KERNEL_PCR_INDEX,digest);
		sprintf(filename,"%s/%s",mountpoint,initrdname);
		calculate_sm3(filename,digest);
		add_pcr_to_set(pcrs,KERNEL_PCR_INDEX,digest);
		pcrs->trust_level=trust_level;
		AddPolicy(pcrs,"PCRP");
//		break;
	}while(1);
	ExportPolicy("PCRP");

	return 0;
}

int add_image_kernelpolicy(void * p_pcrs, char * mountpoint,char * image_desc)
{
	char *boot_file_list[]={
		"/boot/grub/grub.conf",
		"/boot/grub/menu.lst",
		NULL
	};
	struct tcm_pcr_set * pcrs=p_pcrs;
	FILE * fp;
	char *file_arg[MAX_ARG_NUM];
	char filename[512];
	char kernelname[256];
	char initrdname[256];
	int  retval;
	int i;
	char digest[DIGEST_SIZE];
	char desc[512];

	for(i=0;boot_file_list[i]!=NULL;i++)
	{
		sprintf(filename,"%s/%s",mountpoint,boot_file_list[i]);
		fp=fopen(filename,"r");
		if(fp!=NULL)
			break;
	}
	if(boot_file_list[i]==NULL)
	{
		printf("can't find image %s's boot file\n ",image_desc);
		return -EINVAL;
	}

	file_arg[0]=malloc(MAX_LINE_LEN);
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
		sprintf(desc,"image %s 's kernel digest",image_desc);
		pcrs->policy_describe=dup_str(desc,0);
		sprintf(filename,"%s/%s",mountpoint,kernelname);
		calculate_sm3(filename,digest);
		add_pcr_to_set(pcrs,KERNEL_PCR_INDEX,digest);
		sprintf(filename,"%s/%s",mountpoint,initrdname);
		calculate_sm3(filename,digest);
		add_pcr_to_set(pcrs,KERNEL_PCR_INDEX,digest);
		break;
	}while(1);

	return 0;
}

int build_image_pcrlib(char * dev,char *mountpoint,char * image_desc,int trust_level)
{
	char digest[DIGEST_SIZE];
	struct tcm_pcr_set * pcrs;
	struct tcm_pcr_set * boot_pcrs;
	char desc[512];
	int i;
	int ret;

	// build this image's MBR policy  
	boot_pcrs=build_MBR_pcrpolicy(dev,image_desc);
	if(boot_pcrs!=NULL)
	{
		boot_pcrs->trust_level=trust_level;
		AddPolicy(boot_pcrs,"PCRP");
		ExportPolicy("PCRP");
	}
	build_image_kernelpcr(mountpoint,image_desc,trust_level);

	for(i=0;vm_pcr_filelist[i].filelist!=NULL;i++)
	{
		if(vm_pcr_filelist[i].trust_level!=trust_level)
			continue;
		sprintf(desc,"%s %s",image_desc,vm_pcr_filelist[i].tail_desc);
		pcrs=build_filelist_policy(mountpoint,vm_pcr_filelist[i].filelist,
			vm_pcr_filelist[i].pcr_index,desc);
		if(pcrs!=NULL)
		{
			pcrs->trust_level=trust_level;
			AddPolicy(pcrs,"PCRP");
		}
	}

	ExportPolicy("PCRP");
	return 0;
}
int build_filelist_pcr( void * pcr, char ** filelist, int pcr_no)
{
	struct tcm_pcr_set * pcrs=pcr;
	char namebuf[512];
	char digest[DIGEST_SIZE];
	int ret;
	int i;

	if(pcr==NULL)
		return -EINVAL;
	if((pcr_no<0) || (pcr_no>24))
		return -EINVAL;
	
	for(i=0;filelist[i]!=NULL;i++)
	{
		ret=calculate_sm3(filelist[i],digest);
		if(ret<0)
			return ret;
		usleep(10);
		add_pcr_to_set(pcrs,pcr_no,digest);
	}
	return 0;
}

int build_vm_filelist_pcr( void * pcr, char ** filelist, int pcr_no)
{
	struct tcm_pcr_set * pcrs=pcr;
	char namebuf[512];
	char digest[DIGEST_SIZE];
	int ret;
	int i;

	if(pcr==NULL)
		return -EINVAL;
	if((pcr_no<0) || (pcr_no>24))
		return -EINVAL;
	
	for(i=0;filelist[i]!=NULL;i++)
	{
		sprintf(namebuf,"./mnt/%s",filelist[i]);
		ret=calculate_sm3(namebuf,digest);
		if(ret<0)
			return ret;
		usleep(10);
		add_pcr_to_set(pcrs,pcr_no,digest);
	}
	return 0;
}

int build_compute_boot_pcrs(char * dev,char * compute_desc,void ** pcrs)
{
	char digest[DIGEST_SIZE];
	struct tcm_pcr_set * boot_pcrs;
	char desc[512];
	int i;
	int ret;

	*pcrs=NULL;
	// build this image's MBR policy  
	boot_pcrs=build_MBR_pcrpolicy(dev,compute_desc);
	if(boot_pcrs==NULL)
		return -EINVAL;
	add_filelist_policy(NULL,compute_pcr_filelist[0].filelist,
			compute_pcr_filelist[0].pcr_index,boot_pcrs);
	*pcrs=boot_pcrs;
	return 0;
}

int build_compute_running_pcrs(char * dev,char * compute_desc,void ** pcrs)
{
	char digest[DIGEST_SIZE];
	struct tcm_pcr_set * running_pcrs;
	char desc[512];
	int i;
	int ret;
	
	*pcrs=NULL;

	// build this image's MBR policy  
	running_pcrs=build_filelist_policy(NULL,compute_pcr_filelist[1].filelist,
			compute_pcr_filelist[1].pcr_index,compute_desc);
	if(running_pcrs==NULL)
		return -EINVAL;
	for(i=2;compute_pcr_filelist[i].filelist!=NULL;i++)
	{
		ret=add_filelist_policy(NULL,compute_pcr_filelist[i].filelist,
			compute_pcr_filelist[i].pcr_index,running_pcrs);
	}
	*pcrs=running_pcrs;
	return 0;
}

int build_image_boot_pcrs(char * dev,char * mountpoint,char * image_desc, void ** pcrs)
{
	char digest[DIGEST_SIZE];
	struct tcm_pcr_set * boot_pcrs;
	char desc[512];
	int i;
	int ret;

	*pcrs=NULL;
	// build this image's MBR policy  
	boot_pcrs=build_MBR_pcrpolicy(dev,image_desc);
//	boot_pcrs=build_empty_pcr_set();
	if(boot_pcrs==NULL)
		return -EINVAL;
	add_image_kernelpolicy(boot_pcrs,mountpoint,image_desc);
	*pcrs=boot_pcrs;
	return 0;
}

int build_image_running_pcrs(char * dev,char * mountpoint,char * image_desc,void ** pcrs)
{
	char digest[DIGEST_SIZE];
	struct tcm_pcr_set * running_pcrs;
	char desc[512];
	int i;
	int ret;
	

	// build this image's MBR policy  
	*pcrs=NULL;
	running_pcrs=build_filelist_policy(mountpoint,image_pcr_filelist[0].filelist,
			image_pcr_filelist[0].pcr_index,image_desc);
	if(running_pcrs==NULL)
		return -EINVAL;
	for(i=1;image_pcr_filelist[i].filelist!=NULL;i++)
	{
		ret=add_filelist_policy(NULL,image_pcr_filelist[i].filelist,
			image_pcr_filelist[i].pcr_index,running_pcrs);
	}
	*pcrs=running_pcrs;
	return 0;
}


int build_entity_policy(char * uuid,void * platform_pcrs,void * boot_pcrs,void * runtime_pcrs,char * policy_describe, void ** entity_policy)
{
	struct tcm_pcr_set * pcrs;
	struct vm_policy * policy;
	policy=malloc(sizeof(struct vm_policy));
	if(policy==NULL)
		return -ENOMEM;
	memset(policy,0,sizeof(struct vm_policy));
	strncpy(policy->uuid,uuid,DIGEST_SIZE*2);

	*entity_policy=NULL;
	int i;
	for(i=0;i<3;i++)
	{
		switch(i){
			case 0:
				pcrs=platform_pcrs;
				if(pcrs!=NULL)
					strncpy(policy->platform_pcr_uuid,pcrs->uuid,DIGEST_SIZE*2);
				break;
			case 1:
				pcrs=boot_pcrs;
				if(pcrs!=NULL)
					strncpy(policy->boot_pcr_uuid,pcrs->uuid,DIGEST_SIZE*2);
				break;
			case 2:
				pcrs=runtime_pcrs;
				if(pcrs!=NULL)
					strncpy(policy->runtime_pcr_uuid,pcrs->uuid,DIGEST_SIZE*2);
				break;
			default:
				break;
		}
	}
	policy->policy_describe=dup_str(policy_describe,0);	 
	*entity_policy=policy;
	return 0;
}

int build_nova_vm_policy(char * uuid,void ** boot_pcrs, void ** running_pcrs,void ** policy)
{

	char cmd[512];
	char desc[512];
	char namebuf[512];
	char digest[DIGEST_SIZE];
	struct policy_file * pfile;
	struct vm_policy * vm_policy;
	void * struct_template;
	int ret;
	void * sec_respool;
	void * sec_res;


        sprintf(namebuf,"/var/lib/nova/instances/%s/disk",uuid);

	char dev[DIGEST_SIZE*2];
	char mountpoint[DIGEST_SIZE*2];
	char part_dev[DIGEST_SIZE*2];

	/*

	sprintf(dev,"/dev/nbd%d",devno);
	sprintf(mountpoint,"./mnt%d",devno);
	*/
	sec_respool=find_sec_respool("image_mntpoint");
	ret=sec_respool_getres(sec_respool,&sec_res);
	sec_resource_getvalue(sec_res,"dev_name",dev);
	sec_resource_getvalue(sec_res,"mount_path",mountpoint);

	sprintf(cmd,"mkdir %s",mountpoint);
	system(cmd);  

	mount_image(namebuf,dev,mountpoint);

	ret=build_image_boot_pcrs(dev,mountpoint,uuid,boot_pcrs);
	ret=build_image_running_pcrs(dev,mountpoint,uuid,running_pcrs);

	ret=build_entity_policy(uuid,NULL,*boot_pcrs,*running_pcrs,uuid,&vm_policy);


	if(vm_policy!=NULL)
	AddPolicy(vm_policy,"VM_P");
	umount_image(dev,mountpoint);
	sprintf(cmd,"rmdir %s",mountpoint);
	system(cmd);  
	ExportPolicy("VM_P");
	*policy=vm_policy;
	return 0;
}

//int build_glance_image_pcrlib(char * uuid,int devno,char * image_desc,int trust_level)
int build_glance_image_pcrlib(char * uuid,char * image_desc,int trust_level)
{

	char cmd[512];
	char desc[512];
	char namebuf[512];
	char digest[DIGEST_SIZE];
	struct policy_file * pfile;
	void * struct_template;
	int ret;
	void * sec_respool;
	void * sec_res;


        sprintf(namebuf,"/var/lib/glance/images/%s",uuid);

	char dev[DIGEST_SIZE*2];
	char part_dev[DIGEST_SIZE*2];
	char mountpoint[DIGEST_SIZE*2];

	/*

	sprintf(dev,"/dev/nbd%d",devno);
	sprintf(mountpoint,"./mnt%d",devno);
	*/
	sec_respool=find_sec_respool("image_mntpoint");
	ret=sec_respool_getres(sec_respool,&sec_res);
	sec_resource_getvalue(sec_res,"dev_name",dev);
	sec_resource_getvalue(sec_res,"mount_path",mountpoint);

	sprintf(cmd,"mkdir %s",mountpoint);
	system(cmd);  

	mount_image(namebuf,dev,mountpoint);
	
	ret=build_image_pcrlib(dev,mountpoint,image_desc,trust_level);
	umount_image(dev,mountpoint);
	sprintf(cmd,"rmdir %s",mountpoint);
	system(cmd);  
	return 0;
}

//int build_glance_image_policy(char * uuid,void ** boot_pcrs, void ** running_pcrs,int devno,void ** policy)
int build_glance_image_policy(char * uuid,void ** boot_pcrs, void ** running_pcrs,void ** policy)
{

	char cmd[512];
	char desc[512];
	char namebuf[512];
	char digest[DIGEST_SIZE];
	struct policy_file * pfile;
	struct vm_policy * image_policy;
	void * struct_template;
	int ret;
	void * sec_respool;
	void * sec_res;

	struct tcm_pcr_set * image_boot_pcrs;
	struct tcm_pcr_set * image_running_pcrs;


        sprintf(namebuf,"/var/lib/glance/images/%s",uuid);

	char dev[DIGEST_SIZE*2];
	char part_dev[DIGEST_SIZE*2];
	char mountpoint[DIGEST_SIZE*2];

	/*

	sprintf(dev,"/dev/nbd%d",devno);
	sprintf(mountpoint,"./mnt%d",devno);
	*/
	sec_respool=find_sec_respool("image_mntpoint");
	ret=sec_respool_getres(sec_respool,&sec_res);
	sec_resource_getvalue(sec_res,"dev_name",dev);
	sec_resource_getvalue(sec_res,"mount_path",mountpoint);

	sprintf(cmd,"mkdir %s",mountpoint);
	system(cmd);  

	mount_image(namebuf,dev,mountpoint);
	
	ret=build_image_boot_pcrs(dev,mountpoint,uuid,&image_boot_pcrs);
	ret=build_image_running_pcrs(dev,mountpoint,uuid,&image_running_pcrs);

	ret=build_entity_policy(uuid,NULL,image_boot_pcrs,image_running_pcrs,uuid,&image_policy);

	if(image_policy!=NULL)
	AddPolicy(image_policy,"IMGP");
	umount_image(dev,mountpoint);
	sprintf(cmd,"rmdir %s",mountpoint);
	system(cmd);  
	ExportPolicy("IMGP");
	*boot_pcrs=image_boot_pcrs;
	*running_pcrs=image_running_pcrs;
	*policy=image_policy;
	return 0;
}

int build_nova_vm_pcrlib(char * uuid,char * image_desc,int trust_level)
{

	char cmd[512];
	char desc[512];
	char namebuf[512];
	char digest[DIGEST_SIZE];
	struct policy_file * pfile;
	void * struct_template;
	int ret;
	void * sec_respool;
	void * sec_res;


        sprintf(namebuf,"/var/lib/nova/instances/%s/disk",uuid);

	char dev[DIGEST_SIZE*2];
	char part_dev[DIGEST_SIZE*2];
	char mountpoint[DIGEST_SIZE*2];

	/*

	sprintf(dev,"/dev/nbd%d",devno);
	sprintf(mountpoint,"./mnt%d",devno);
	*/
	sec_respool=find_sec_respool("image_mntpoint");
	ret=sec_respool_getres(sec_respool,&sec_res);
	sec_resource_getvalue(sec_res,"dev_name",dev);
	sec_resource_getvalue(sec_res,"mount_path",mountpoint);

	sprintf(cmd,"mkdir %s",mountpoint);
	system(cmd);  

	mount_image(namebuf,dev,mountpoint);
	
	ret=build_image_pcrlib(dev,mountpoint,image_desc,trust_level);
	umount_image(dev,mountpoint);
	sprintf(cmd,"rmdir %s",mountpoint);
	system(cmd);  
	return 0;
}
void ** create_verify_list(char * policy_type,char * entity_uuid,int list_num)
{
	int j;
	struct verify_info ** verify_list;
	BYTE * blob=malloc(sizeof(struct verify_info *)*(list_num+1)+
		sizeof(struct verify_info)*list_num);
	if(blob==NULL)
		return NULL;
	memset(blob,0,sizeof(struct verify_info *)*(list_num+1)+
		sizeof(struct verify_info)*list_num);
	verify_list=(struct verify_info *)blob;

	for(j=0;j<list_num;j++)
	{
		verify_list[j]=blob+sizeof(struct verify_info *)*(list_num+1)+
			sizeof(struct verify_info)*j;
		strncpy(verify_list[j]->policy_type,policy_type,4);
		strncpy(verify_list[j]->entity_uuid,entity_uuid,DIGEST_SIZE*2);
	}
	strncpy(verify_list[0]->verify_data_uuid,entity_uuid,DIGEST_SIZE*2);
	return verify_list;
}

#define PCR_SIZE 20
int verify_pcrs_set(void * v_pcrs,void * v_list)
{
	struct verify_info ** verify_list=(struct verify_info **)v_list;
	struct tcm_pcr_set * pcrs=(struct tcm_pcr_set *)v_pcrs;
	struct tcm_pcr_set * verify_pcrs;
	struct tcm_pcr_set * comp_pcrs;
	char digest[DIGEST_SIZE];
	char uuid[DIGEST_SIZE*2+1];
	int i,j;
	int offset;
	int maxno;
	int trust_level;

	if(v_pcrs==NULL)
		return 0;

	trust_level=verify_list[0]->trust_level;

	for(i=0;verify_list[i]!=NULL;i++);
	maxno=i;

	for(i=0;i<maxno;i++)
	{
		if(verify_list[i]->verify_data_uuid[0]==0)
			break;
	}

	for(j=0;j<24;j++)
	{	
		if(i>=maxno)
		{
			trust_level=0;
			break;
		}
		verify_pcrs=get_single_pcr_from_set(pcrs,j);
		if(verify_pcrs==NULL)
			continue;
		memcpy(	verify_list[i]->verify_data_uuid,verify_pcrs->uuid,DIGEST_SIZE*2);
//		comp_pcrs=FindPolicy(verify_pcrs,"PCRP");
		FindPolicy(verify_pcrs,"PCRP",&comp_pcrs);
		if(comp_pcrs==NULL)
		{
			verify_list[i]->trust_level=-1;
			verify_list[i]->info=dup_str("Verify Failed!",0);
			verify_list[i]->info_len=strlen(verify_list[i]->info)+1;
			trust_level=-1;
		}
		else
		{
			verify_list[i]->trust_level=comp_pcrs->trust_level;
			if(trust_level==0)
				trust_level=comp_pcrs->trust_level;
			else if(trust_level>0)
			{
				if(comp_pcrs->trust_level>trust_level)
					trust_level=comp_pcrs->trust_level;
			}
			verify_list[i]->info=dup_str(comp_pcrs->policy_describe,0);
			verify_list[i]->info_len=strlen(verify_list[i]->info)+1;
			
		}
		i++;
	}
	verify_list[0]->trust_level=trust_level;
	return trust_level;
}
