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
#include "../include/connector.h"
#include "../include/logic_baselib.h"
#include "../include/connector.h"
#include "../include/sec_entity.h"
#include "../include/main_proc_init.h"

#include "file_dealer.h"

int file_dealer_init(void * sub_proc,void * para)
{
	int ret=0;
	return ret;
}

int file_dealer_start(void * sub_proc,void * para)
{
	int ret;
	void * recv_msg;
	void * context;
	int i;
	const char * type;

	printf("begin file_dealer start process! \n");

	for(i=0;i<3000*1000;i++)
	{
		usleep(time_val.tv_usec);
		ret=sec_subject_recvmsg(sub_proc,&recv_msg);
		if(ret<0)
			continue;
		if(recv_msg==NULL)
			continue;

 		type=message_get_recordtype(recv_msg);
		if(type==NULL)
		{
			message_free(recv_msg);
			continue;
		}
		if(strncmp(type,"FILD",4)==0)
		{
			proc_file_receive(sub_proc,recv_msg);
		}
		else if(strncmp(type,"FILQ",4)==0)
		{
			proc_file_send(sub_proc,recv_msg);
		}
		else
		{
			message_free(recv_msg);
		}
	}

	return 0;
};


int _is_samefile_exists(void * record)
{
	struct policyfile_data * pfdata=record;
	char digest[DIGEST_SIZE];
        char uuid[DIGEST_SIZE*2];
	int fd;
	int ret;
	fd=open(pfdata->filename,O_RDONLY);
	if(fd>0)
	{
		close(fd);
		ret=calculate_sm3(pfdata->filename,digest);
		if(ret<0)
			return ret;
		digest_to_uuid(digest,uuid);
		if(strncmp(pfdata->uuid,uuid,DIGEST_SIZE*2)!=0)
		{
			return 1;
		}
		return 0;
	}
	return 2;	

}


int proc_file_receive(void * sub_proc,void * message)
{
	struct policyfile_data * pfdata;
	struct policyfile_store * storedata;
	int ret;

	printf("begin file receive!\n");
	char buffer[1024];
	char digest[DIGEST_SIZE];
        char uuid[DIGEST_SIZE*2];
	int blobsize=0;
	int fd;

	ret=message_get_record(message,&pfdata,0);
	if(ret<0)
		return -EINVAL;
	if(pfdata->total_size==pfdata->data_size)
	{
		// judge if there exists a same-name file 
		switch(ret=_is_samefile_exists(pfdata))
		{
			case 0:     // samefile exists
				printf("file %s has existed!\n",pfdata->filename);
				return 0;
			case 1:
				printf("overwrite the file %s!\n",pfdata->filename);
				ret=remove(pfdata->filename);
				if(ret<0)
					return ret;
			case 2:
				ret=get_filedata_from_message(message);
				return ret;

			default:
				return ret;
		}
	}
	else
	{
		ret=FindPolicy(pfdata->uuid,"FILS",&storedata);
		if(ret<0)
			return ret;
		if(storedata==NULL)
		{
			switch(ret=_is_samefile_exists(pfdata))
			{
				case 0:     // samefile exists
					printf("file %s has existed!\n",pfdata->filename);
					return 0;
				case 1:
					printf("overwrite the file %s!\n",pfdata->filename);
					ret=remove(pfdata->filename);
					if(ret<0)
						return ret;
				case 2:
					break;

				default:
					return ret;
			}
		}


		storedata=malloc(sizeof(struct policyfile_store));
		if(storedata==NULL)
			return -ENOMEM;
		memcpy(storedata->uuid,pfdata->uuid,DIGEST_SIZE*2);				
		storedata->filename=dup_str(pfdata->filename,0);
		storedata->file_size=pfdata->total_size;
		storedata->block_size=256;
		storedata->block_num=(pfdata->total_size+(256-1))/256;
		storedata->mark_len=(storedata->block_num+7)/8;
		storedata->marks=malloc(storedata->mark_len);
		memset(storedata->marks,0,storedata->mark_len);
		int site= pfdata->offset/256;
		bitmap_set(storedata->marks,site);
		AddPolicy(storedata,"FILS");	
	
		if(!bitmap_is_allset(storedata->marks,storedata->block_num))
		{
			printf("get file %s succeed!\n",pfdata->filename);
			return pfdata->data_size;
		}
	}

	return 0;
}
int proc_file_send(void * sub_proc,void * message)
{
/*
	struct policyfile_data * senddata;
	struct policyfile_req  * reqdata;
	int ret;

	printf("begin file send!\n");
	char buffer[1024];
	char digest[DIGEST_SIZE];
	int blobsize=0;
	int fd;

	ret=message_get_record(message,&reqdata,0);
	if(ret<0)
		return -EINVAL;
	
	if(reqdata->filename==NULL)
		return -EINVAL;
	{
		ret=get_filedata_from_message(message);
		if(ret<0)
			return ret;
	}
	else
	{
		ret=FindPolicy(reqdata->uuid,"FILS",&storedata);
		if(ret<0)
			return ret;
		if(storedata==NULL)
		{
			storedata=malloc(sizeof(struct policyfile_store));
			if(storedata==NULL)
				return -ENOMEM;
			memcpy(storedata->uuid,reqdata->uuid,DIGEST_SIZE*2);				
			storedata->filename=dup_str(reqdata->filename,0);
			storedata->file_size=reqdata->total_size;
			storedata->block_size=256;
			storedata->block_num=(reqdata->total_size+(256-1))/256;
			storedata->mark_len=(storedata->block_num+7)/8;
			storedata->marks=malloc(storedata->mark_len);
			memset(storedata->marks,0,storedata->mark_len);
		}					
		int site= reqdata->offset/256;
		bitmap_set(storedata->marks,site);
		AddPolicy(storedata,"FILS");	
	
		if(!bitmap_is_allset(storedata->marks,storedata->block_num))
			return reqdata->data_size;
	}
	printf("get file %s succeed!\n",reqdata->filename);
*/
	return 0;
}
