#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
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
#include "../include/valuename.h"
#include "../include/message_struct.h"
#include "../include/message_struct_desc.h"
#include "../include/vmlist.h"
#include "../include/vtpm_struct.h"
#include "../include/vm_policy.h"
#include "../include/logic_baselib.h"
#include "../include/sec_entity.h"

#include "general_lib_init.h"

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
		
//		ret=struct_2_blob(record_data,blob,struct_template);
//		if(ret<0)
//			return -EINVAL;
//		if(ret<DIGEST_SIZE*2)
//			return -EINVAL;
//
///		ret=calculate_context_sm3(blob+DIGEST_SIZE*2,ret-DIGEST_SIZE*2,digest);
//		if(ret<0)
//			return -EINVAL;
//		digest_to_uuid(digest,record_data);
					
		AddPolicy(record_data,type);
		offset=json_solve_str(&root,buffer+curr_offset);
		if(offset<0)
			break;
	}
	ExportPolicy(type);
	return 0;
}
