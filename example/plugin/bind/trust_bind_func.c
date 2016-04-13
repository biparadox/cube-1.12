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
	struct vTPM_wrappedkey * bind_key;
    	struct vTPM_publickey * bind_pubkey;
	TSS_HKEY hBindKey;
	TSS_HKEY hBindPubKey;
};

int bind_pubkey_memdb_init()
{
	int ret;
	char * bindpubkeyname="pubkey/bindpubkey";
	struct vTPM_publickey	*local_bindpubkey;

	local_bindpubkey=malloc(sizeof(struct vTPM_publickey));
	if(local_bindpubkey==NULL)
		return -ENOMEM;

	ret=create_pubkey_struct(local_bindpubkey,NULL,NULL,bindpubkeyname);	
	if(ret<0)
		return ret;

	AddPolicy(local_bindpubkey,"PUBK");
       	ExportPolicy("PUBK");
	return 0;
}

int bind_key_memdb_init()
{
	int ret;
	char * bindkeyname="privkey/bindkey";
	struct vTPM_wrappedkey	*local_bindkey;

	local_bindkey=malloc(sizeof(struct vTPM_wrappedkey));
	if(local_bindkey==NULL)
		return -ENOMEM;

	ret=create_blobkey_struct(local_bindkey,NULL,NULL,"kkk",bindkeyname);	
	if(ret<0)
		return ret;

	AddPolicy(local_bindkey,"BLBK");
       	ExportPolicy("BLBK");
	return 0;
}
int trust_bind_init(void * sub_proc,void * para)
{
	int ret;
	// add youself's plugin init func here
	TSS_RESULT result;	
	result=TESI_Local_ReloadWithAuth("ooo","sss");
	if(result!=TSS_SUCCESS)
	{
		printf("open tpm error %d!\n",result);
		return -ENFILE;
	}

	ret=bind_key_memdb_init();
	if(ret<0)
	{
		printf("load bindkey error %d!\n",ret);
	}
	ret=bind_pubkey_memdb_init();
	if(ret<0)
	{
		printf("load bindpubkey error %d!\n",ret);
	}

	struct bind_proc_pointer * bind_pointer;
	bind_pointer= malloc(sizeof(struct bind_proc_pointer));
	if(bind_pointer==NULL)
		return -ENOMEM;
	memset(bind_pointer,0,sizeof(struct bind_proc_pointer));

	ret=GetFirstPolicy(&bind_pointer->bind_pubkey,"PUBK");
	if(bind_pointer->bind_pubkey==NULL)
	{
		printf("There is no bind_pubkey!\n");
	}
	else
	{
	
		result=TESI_Local_ReadPubKey(&(bind_pointer->hBindPubKey),bind_pointer->bind_pubkey->key_filename);
		if(result!=TSS_SUCCESS)
		{
			printf("load bindpubkey error %d!\n",result);
		}
	}

	ret=GetFirstPolicy(&bind_pointer->bind_key,"BLBK");
	if(bind_pointer->bind_key==NULL)
	{
		printf("There is no bindkey!\n");
	}
	else
	{
	
		result=TESI_Local_ReadKeyBlob(&(bind_pointer->hBindKey),bind_pointer->bind_key->key_filename);
		if(result!=TSS_SUCCESS)
		{
			printf("load bindkey error %d!\n",result);
		}
		result=TESI_Local_LoadKey(bind_pointer->hBindKey,NULL,bind_pointer->bind_key->keypass);
		if(result!=TSS_SUCCESS)
		{
			printf("load bindkey error %d!\n",result);
			return -ENFILE;
		}
	}


	void * context;
	ret=sec_subject_getcontext(sub_proc,&context);
	if(ret<0)
		return ret;
	ret=sec_object_setpointer(context,bind_pointer);
	if(ret<0)
		return ret;

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
		if(message_get_flag(recv_msg) & MSG_FLAG_CRYPT)
			proc_unbind_message(sub_proc,recv_msg);
		else
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

	void * context;
	ret=sec_subject_getcontext(sub_proc,&context);
	if(ret<0)
		return ret;
	bind_pointer=sec_object_getpointer(context);
	if(bind_pointer==NULL)
		return -EINVAL;

		
	void * blob;
	int blob_size;

	void* bind_blob;
	int bind_blob_size;

	blob_size=message_get_blob(message,&blob);
	if(blob_size<=0)
		return -EINVAL;

	result=TESI_Local_BindBuffer(blob,blob_size,bind_pointer->hBindKey,&bind_blob,&bind_blob_size);
	if ( result != TSS_SUCCESS )
	{
		return -EINVAL;
	}
	

	message_set_blob(message,bind_blob,bind_blob_size);
	message_set_flag(message,MSG_FLAG_CRYPT);

	sec_subject_sendmsg(sub_proc,message);
	return ret;
}

int proc_unbind_message(void * sub_proc,void * message)
{
	TSS_RESULT result;
	struct bind_proc_pointer * bind_pointer;
	int i;
	int ret;

	void * context;
	ret=sec_subject_getcontext(sub_proc,&context);
	if(ret<0)
		return ret;
	bind_pointer=sec_object_getpointer(context);
	if(bind_pointer==NULL)
		return -EINVAL;

		
	void * blob;
	int blob_size;

	void* bind_blob;
	int bind_blob_size;

	blob_size=message_get_blob(message,&blob);
	if(blob_size<=0)
		return -EINVAL;

/*
	result=TESI_Local_ReadKeyBlob(&(bind_pointer->hBindKey),bind_pointer->bind_key->key_filename);
	if(result!=TSS_SUCCESS)
	{
		printf("load bindkey error %d!\n",result);
		return -ENFILE;
	}
	result=TESI_Local_LoadKey(bind_pointer->hBindKey,NULL,bind_pointer->bind_key->keypass);
	if(result!=TSS_SUCCESS)
	{
		printf("load bindkey error %d!\n",result);
		return -ENFILE;
	}
*/	
	
	result=TESI_Local_UnBindBuffer(blob,blob_size,bind_pointer->hBindKey,&bind_blob,&bind_blob_size);
	if ( result != TSS_SUCCESS )
	{
		return -EINVAL;
	}
	
	message_set_blob(message,bind_blob,bind_blob_size);
	int flag=message_get_flag(message);
	message_set_flag(message,flag&(~MSG_FLAG_CRYPT));

	sec_subject_sendmsg(sub_proc,message);
	return ret;
}
