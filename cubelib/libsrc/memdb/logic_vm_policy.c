/*************************************************
*************************************************/

#ifndef USER_MODE

#include <asm/uaccess.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/sched.h>

#else


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "../include/kernel_comp.h"
#include "../include/list.h"
#include "../include/attrlist.h"

#endif

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/extern_struct.h"
#include "../include/extern_interface.h"
#include "../include/extern_struct_desc.h"
#include "../include/extern_defno.h"

#include "../include/logic_baselib.h"
#include "../include/vm_policy.h"
#include "../include/vm_policy_desc.h"

#include "logic_compare.h"
#define DIGEST_SIZE 32
#define PCR_SELECT_NUM 24
#define PCR_SIZE  20

void * build_policy_file(char * creater,char *policy_type,BYTE * key_uuid,char * filename)
{
	struct policy_file * policy;
	BYTE digest[DIGEST_SIZE];
	BYTE *buffer;


	policy=malloc(sizeof(struct policy_file));
	if(policy==NULL)
		return NULL;
	buffer=kmalloc(128,GFP_KERNEL);
	if(buffer==NULL)
	{
		free(policy);
		return NULL;
	}
	memset(buffer,0,128);
	memset(policy,0,sizeof(struct policy_file));
	if(creater!=NULL)
		policy->creater=dup_str(creater,0);
	if(policy_type!=NULL)
		memcpy(policy->policy_type,policy_type,4);
	if(key_uuid!=NULL)
	{
		strncpy(buffer,creater,40);
		int offset=strlen(buffer)+1;
		if(offset>40)
			offset=40;
		strncpy(buffer+offset,key_uuid,DIGEST_SIZE*2);
		offset+=DIGEST_SIZE*2;
		calculate_context_sm3(buffer,offset,digest);
		digest_to_uuid(digest,policy->creater_auth_uuid);
	}

	policy->policy_path=dup_str(filename,0);
	calculate_sm3(filename,digest);
	digest_to_uuid(digest,policy->file_uuid);
//	compute_policy_set_uuid(policy);
	free(buffer);
	return policy;
}	
int general_lib_init(char * type,void * para)
{
	char filename[12];
	FILE * file;
	int datalen;
	int offset;
	int curr_offset;
	char * buffer;
	void * record_data;
	void * root;
	void * struct_template;
	int ret;

	if(type==NULL)
		return -EINVAL;
	sprintf(filename,"%4.4s.list",type);

	file=fopen(filename,"r");
	if(file==NULL)
	{
		printf("Unable to read file %s. \n",filename);
		return -EINVAL;
	}
	fseek(file,0,SEEK_END);
	datalen=ftell(file);
	fseek(file,0,SEEK_SET);

	buffer=(BYTE *)malloc(datalen);
	if(buffer==NULL)
		return -ENOMEM;
	ret=fread(buffer,datalen,1,file);
	if(ret!=1)
	{
		fclose(file);
	        free(buffer);
       		printf("I/O Error reading %s list file",type);
 		return -EINVAL;
	}
	fclose(file);

	struct_template=load_record_template(type);
	if(struct_template==NULL)
		return -EINVAL;
	curr_offset=0;
	offset=json_solve_str(&root,buffer);

	while(	offset+curr_offset<datalen)
	{
		curr_offset+=offset;
		ret=alloc_struct(&record_data,struct_template);
		if(ret<0)
			break;
		ret=json_2_struct(root,record_data,struct_template);
		if(ret<0)
			break;
		AddPolicy(record_data,type);
		offset=json_solve_str(&root,buffer+curr_offset);
		if(offset<0)
			break;
	}
	ExportPolicy(type);
	return 0;
}

int general_uuid_lib_init(char * type,void * para)
{
	char filename[12];
	FILE * file;
	int datalen;
	int offset;
	int curr_offset;
	char * buffer;
	void * record_data;
	void * root;
	void * struct_template;
	int ret;
	BYTE digest[DIGEST_SIZE];
	BYTE blob[1024];


	if(type==NULL)
		return -EINVAL;
	sprintf(filename,"%4.4s.list",type);

	file=fopen(filename,"r");
	if(file==NULL)
	{
		printf("Unable to read file %s. \n",filename);
		return -EINVAL;
	}
	fseek(file,0,SEEK_END);
	datalen=ftell(file);
	fseek(file,0,SEEK_SET);

	buffer=(BYTE *)malloc(datalen);
	if(buffer==NULL)
		return -ENOMEM;
	ret=fread(buffer,datalen,1,file);
	if(ret!=1)
	{
		fclose(file);
	        free(buffer);
       		printf("I/O Error reading %s list file",type);
 		return -EINVAL;
	}
	fclose(file);

	struct_template=load_record_template(type);
	if(struct_template==NULL)
		return -EINVAL;
	curr_offset=0;
	offset=json_solve_str(&root,buffer);

	while(	offset+curr_offset<datalen)
	{
		curr_offset+=offset;
		ret=alloc_struct(&record_data,struct_template);
		if(ret<0)
			break;
		ret=json_2_struct(root,record_data,struct_template);
		if(ret<0)
			break;

		ret=entity_hash_uuid(type,record_data);
		if(ret<0)
			return ret;
		
		AddPolicy(record_data,type);
		offset=json_solve_str(&root,buffer+curr_offset);
		if(offset<0)
			break;
	}
	ExportPolicy(type);
	return 0;
}
