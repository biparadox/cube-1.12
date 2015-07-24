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
#include "../include/tesi.h"
#include "../include/openstack_trust_lib.h"
#include "../include/sec_entity.h"
//#include "./verifier_func.h"
#include "readconfig.h"

#include "trust_policy.h"
#include "trust_policy_desc.h"
#include "cloud_config.h"
#include "local_func.h"
#include "cloud_policy.h"


#define MBR_PCR_INDEX  4
#define KERNEL_PCR_INDEX  10
#define SECURE_PCR_INDEX  11
#define VMM_PCR_INDEX  12
#define TRUSTBUS_PCR_INDEX  13
#define EXPAND_PCR_INDEX  23

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

int read_json_policy(void ** root, FILE * file)
{
	char filename[12];
	int datalen;
	int offset;
	int curr_offset;
	char * buffer;
	void * record_data;
	void * struct_template;
	int ret;

	if(root==NULL)
		return -EINVAL;

	offset=ftell(file);

	fseek(file,0,SEEK_END);
	
	datalen=ftell(file)-offset;
	fseek(file,offset,SEEK_SET);

	if(datalen>4096)
		datalen=4096;
	if(datalen==0)
	{
		fclose(file);
		return 0;
	}
	
	buffer=malloc(4096);
	if(buffer==NULL)
		return -ENOMEM;
	ret=fread(buffer,datalen,1,file);
	if(ret!=1)
	{
		fclose(file);
	  	free(buffer);
       		printf("I/O Error reading file");
 		return -EINVAL;
	}

	curr_offset=offset;
	offset=json_solve_str(root,buffer);
	if(offset<0)
	{
		free(buffer);
		return offset;
	}
	fseek(file,offset,SEEK_CUR);
	return offset;
}


/*
int make_TF_I_policy(void * node,void ** policy)
{
	void * elem_node;
	struct trust_file_info * policy_struct;
	char * buffer;
	char digest[DIGEST_SIZE];
	int ret;
	void * struct_template;
	*policy=NULL;
	struct_template=load_record_template("TF_I");
	buffer=malloc(4096);
	if(buffer==NULL)
		return -EINVAL;
	ret=alloc_struct(&policy_struct,struct_template);
	if(ret<0)
		return ret;
	if(policy_struct==NULL)
		return -EINVAL;
	ret=json_2_struct(node,policy_struct,struct_template);
	if(ret<0)
		return -EINVAL;
	
	ret=calculate_sm3(policy_struct->name, policy_struct->digest);
	if(ret<0)
		return -EINVAL;
	strcpy(buffer,policy_struct->name);
	int len=strlen(buffer+1);
	memcpy(buffer+len,policy_struct->digest,DIGEST_SIZE);
	calculate_context_sm3(buffer,len+DIGEST_SIZE,digest);
	digest_to_uuid(digest,policy_struct->uuid);

	int stroffset=0;	

	struct_2_json(policy_struct,buffer,struct_template,&stroffset);
	printf("%s\n",buffer);
	free(buffer);
	*policy=policy_struct;
	ret=AddPolicy(policy_struct,"TF_I");
	return ret;
}

int make_TFLI_policy(void * node,void ** policy)
{
	void * elem_node;
	struct trust_file_list * file_list;
	struct trust_file_info * file_info;
 	void * file_node;
	int pcr_index;
	int ret;
	char * buffer;
	int offset=0;
	void * struct_template;
	char digest[DIGEST_SIZE];
	
	elem_node = find_json_elem("pcr_index",node);
	if(elem_node==NULL)
		return -EINVAL;
	struct_template=load_record_template("TFLI");
	ret=alloc_struct(&file_list,struct_template);
	if(file_list==NULL)
		return -ENOMEM;


	ret=get_json_value_from_node(elem_node,&(file_list->pcr_index),sizeof(int));
	if(ret<0)
		return -EINVAL;
	elem_node=find_json_elem("info",node);
	if(elem_node==NULL)
		return -EINVAL;
	
	buffer=malloc(32768);
	if(buffer==NULL)
		return -EINVAL;
	ret=get_json_value_from_node(elem_node,buffer,512);
	if(ret<0)
	{
		free(buffer);
		return ret;
	}
	file_list->info=dup_str(buffer,512);

	elem_node=find_json_elem("filelist",node);
	if(elem_node==NULL)
	{
		free(buffer);
		return -EINVAL;
	}
	file_list->file_num=0;
	file_node=get_first_json_child(elem_node);
	while(file_node!=NULL)
	{
		ret=make_TF_I_policy(file_node,&file_info);
		if(file_info==NULL)
		{
			printf("process file error!");
			free(buffer);
			return -EINVAL;
		}
		memcpy(buffer+file_list->file_num*DIGEST_SIZE*2,file_info->uuid,DIGEST_SIZE*2);
		file_list->file_num++;	
		file_node=get_next_json_child(elem_node);
	}
	file_list->uuid_list=malloc(DIGEST_SIZE*2*file_list->file_num);
	if(file_list->uuid_list==NULL)
	{
		free(buffer);
		return -ENOMEM;
	}
	memcpy(file_list->uuid_list,buffer,DIGEST_SIZE*2*file_list->file_num);
	*policy=file_list;

	offset+=sizeof(file_list->pcr_index);
	memcpy(buffer+offset,&(file_list->file_num),sizeof(file_list->file_num));
	offset+=sizeof(file_list->pcr_index);
	memcpy(buffer+offset,file_list->uuid_list,file_list->file_num*DIGEST_SIZE*2);
	offset+=file_list->file_num*DIGEST_SIZE*2;
	calculate_context_sm3(buffer,offset,digest);
	digest_to_uuid(digest,file_list->uuid);
		
	int stroffset=0;	

	struct_2_json(file_list,buffer,struct_template,&stroffset);
	printf("%s\n",buffer);
	memcpy(buffer+offset,&(file_list->pcr_index),sizeof(file_list->pcr_index));

	free(buffer);
	ret=AddPolicy(file_list,"TFLI");
	return ret;
}
*/
int main(int argc,char ** argv)
{
	char cmd[512];
	int retval;
	char local_uuid [DIGEST_SIZE*2];
	char * proc_name = "policy_gen";
	char hostname [DIGEST_SIZE*2];
	struct verify_info ** verify_list;
    	const int bufsize=1024;
    	char buffer[bufsize];
	void *root;

	char *file_arg[MAX_ARG_NUM];
	FILE * fp;
	void * pcrs;
	int i;
	struct trust_file_list * file_list;

	if(argc!=2)
	{
		printf("error usage: should be %s <list config file >",argv[0]);
		return -EINVAL;
	}
		
    	fp = fopen(argv[1],"r");
    	if(fp==NULL)
        	return -EINVAL;
    	int read_offset;
  	int solve_offset;
    	int buffer_left=0;
    	int policy_num=0;

    	openstack_trust_lib_init();
      	sec_respool_list_init();

	retval=read_json_policy(&root,fp);	
	if(retval<0)
	{
		printf("read file %s error %d!\n",argv[1],retval);
		return retval;
	}

    	usleep(time_val.tv_usec);

	retval=register_record_type("TP_H",&trust_policy_head_desc);
	
	void * json_head;
	json_head=find_json_elem("head",root);
	if(json_head==NULL)
		return -EINVAL;  
	void * head_template;
	TP_HEAD policy_head;
	
	head_template=load_record_template("TP_H");
	if(head_template==NULL)
		return -EINVAL;

	memset(&policy_head,0,sizeof(TP_HEAD));

	retval=json_2_struct(json_head,&policy_head,head_template);
	
	int offset=0;
	struct_2_json(&policy_head,buffer,head_template,&offset);

	printf("%s\n",buffer);


    	for(i=0;procdb_init_list[i].name!=NULL;i++)
  	{
		PROCDB_INIT * db_init=&procdb_init_list[i];
	    	if(db_init->record_desc!=NULL)
	    	{
			retval=register_record_type(db_init->name,db_init->record_desc);
		  	if(retval<0)
				return -EINVAL;
	    	}
		
	 	if(db_init->recordlib_ops!=NULL)
	    	{
	   		retval=register_policy_lib(db_init->name,db_init->recordlib_ops);
	  		if(retval<0)
	         	{
		    		printf("register lib %s error!\n",db_init->name);
		    		return retval;
	    	 	}
	         	retval=db_init->init(db_init->name,NULL);
			if(retval<0)
				return -EINVAL;
	    	 	retval=LoadPolicy(db_init->name);
	    	}
    	}

/*
	ExportPolicy("TF_I");
	ExportPolicy("TFLI");

	retval=get_local_uuid(local_uuid);
	printf("this machine's local uuid is %s\n",local_uuid);
	retval=gethostname(hostname,DIGEST_SIZE*2);
	
	build_image_mount_respool(0,16,"image_mntpoint");
	
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
*/
	return 0;
}
		
