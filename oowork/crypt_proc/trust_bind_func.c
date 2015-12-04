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
#include <openssl/rsa.h>
#include <openssl/evp.h>

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/policy_ui.h"
#include "../include/crypto_func.h"
#include "../include/extern_struct.h"
#include "../include/extern_defno.h"
#include "../include/message_struct.h"
#include "../include/logic_baselib.h"
#include "../include/sec_entity.h"
#include "../include/main_proc_init.h"
#include "../include/valuename.h"
#include "../include/expand_define.h"
#include "../include/tesi.h"

#include "../cloud_config.h"
#include "main_proc_func.h"

struct bind_proc_pointer
{
    struct vTPM_publickey * bind_key;
	TSS_HKEY hBindKey;
};

int trust_bind_init(void * sub_proc,void * para)
{
	int ret;
	// add youself's plugin init func here
	TSS_RESULT result;	
	result=TESI_Local_Reload();
	if(result!=TSS_SUCCESS)
	{
		printf("open tpm error %d!\n",result);
		return -ENFILE;
	}
	struct bind_proc_pointer * bind_pointer;
	bind_pointer= malloc(sizeof(struct bind_proc_pointer));
	if(bind_pointer==NULL)
		return -ENOMEM;
	memset(bind_pointer,0,sizeof(struct bind_proc_pointer));

/*
	ret=GetFirstPolicy(&(bind_pointer->bind_key),"PUBK");
	if(bind_pointer->bind_key==NULL)
		return -EINVAL;
	
	result=TESI_Local_ReadPubKey(&(bind_pointer->hBindKey),bind_pointer->bind_key->key_filename);
	if(result!=TSS_SUCCESS)
	{
		printf("load bindkey error %d!\n",result);
		return -ENFILE;
	}
	void * context;
	ret=sec_subject_getcontext(sub_proc,&context);
	if(ret<0)
		return ret;
	ret=sec_object_setpointer(context,bind_pointer);
	if(ret<0)
		return ret;
*/
	return 0;
}

int trust_bind_start(void * sub_proc,void * para)
{
	int ret;
	void * recv_msg;
	int i;
	const char * type;



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
			printf("message format error!\n");
			continue;
		}
		proc_bind_message(sub_proc,recv_msg);
	}

	return 0;
}

int proc_bind_message(void * sub_proc,void * message)
{
	TSS_RESULT result;
	struct bind_proc_pointer * bind_pointer;
	int i;
	int ret;
	struct keyid_expand * key_expand;
	struct vTPM_publickey * pubkey;
	TSS_HKEY hBindKey;

	ret=message_get_define_expand(message,&key_expand,"KEYE");	
	if(ret<0)
		return ret;
	if(key_expand==NULL)
		return -EINVAL;

	ret=FindPolicy(key_expand->keyid,"PUBK",&pubkey);
	if(ret<0)
		return ret;
	if(pubkey==NULL)
		return -EINVAL;
	
	result=TESI_Local_ReadPubKey(&hBindKey,pubkey->key_filename);
	if(result!=TSS_SUCCESS)
	{
		printf("load bindkey error %d!\n",result);
		return -ENFILE;
	}

		
	void * blob;
	int blob_size;

	void* bind_blob;
	int bind_blob_size;

	blob_size=message_output_record_blob(message,&blob);
	if(blob_size<=0)
		return -EINVAL;

//	int fd = open("plain.txt",O_WRONLY|O_CREAT|O_TRUNC);
//	write(fd,blob,blob_size);
//	close(fd);

	result=TESI_Local_BindBuffer(blob,blob_size,hBindKey,&bind_blob,&bind_blob_size);
	if ( result != TSS_SUCCESS )
	{
		return -EINVAL;
	}
	

//	fd = open("cipher.txt",O_WRONLY|O_CREAT|O_TRUNC);
//	write(fd,bind_blob,bind_blob_size);
//	close(fd);

	message_set_blob(message,bind_blob,bind_blob_size);
	message_set_flag(message,MSG_FLAG_CRYPT);

	sec_subject_sendmsg(sub_proc,message);
	return ret;
}
