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

int trust_unbind_init(void * sub_proc,void * para)
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
	return 0;
}

int trust_unbind_start(void * sub_proc,void * para)
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
		proc_unbind_message(sub_proc,recv_msg);
	}

	return 0;
}

int proc_unbind_message(void * sub_proc,void * message)
{
	TSS_RESULT result;
	int i;
	int ret;
	struct keyid_expand * key_expand;
	struct vTPM_wrappedkey * privkey;
	TSS_HKEY hUnBindKey;

	ret=message_get_define_expand(message,&key_expand,"KEYE");	
	if(ret<0)
		return ret;
	if(key_expand==NULL)
		return -EINVAL;

	ret=FindPolicy(key_expand->keyid,"BLBK",&privkey);
	if(ret<0)
		return ret;
	if(privkey==NULL)
		return -EINVAL;

	result=TESI_Local_ReloadWithAuth("ooo","sss");
	if(result!=TSS_SUCCESS)
	{
		printf("open tpm error %d!\n",result);
		return -ENFILE;
	}

	
	result=TESI_Local_ReadKeyBlob(&hUnBindKey,privkey->key_filename);
	if(result!=TSS_SUCCESS)
	{
		printf("read unbindkey error %d!\n",result);
		return -ENFILE;
	}
	result=TESI_Local_LoadKey(hUnBindKey,NULL,privkey->keypass);
	if(result!=TSS_SUCCESS)
	{
		printf("load unbindkey error %d!\n",result);
		return -ENFILE;
	}

	void * blob;
	int blob_size;

	void* bind_blob;
	int bind_blob_size;

	blob_size=message_output_record_blob(message,&blob);
	if(blob_size<=0)
		return -EINVAL;


	result=TESI_Local_UnBindBuffer(blob,blob_size,hUnBindKey,&bind_blob,&bind_blob_size);
	if ( result != TSS_SUCCESS )
	{
		return -EINVAL;
	}
	

	message_set_blob(message,bind_blob,bind_blob_size);
	int flag=message_get_flag(message);
	message_set_flag(message,flag&(~MSG_FLAG_CRYPT));
	ret=message_load_record(message);
	if(ret<0)
		return ret;
	void * expand;
	message_remove_expand(message,"KEYE",&expand);
	sec_subject_sendmsg(sub_proc,message);
	return ret;
}
