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
#include "../include/message_struct.h"
#include "../include/logic_baselib.h"
#include "../include/sec_entity.h"
//#include "../include/main_proc_init.h"
#include "../include/valuename.h"
#include "../include/expand_define.h"
#include "session_msg.h"
#include "user_info.h"
#include "sm4.h"
#include "symm_crypt.h"

static char passwd[DIGEST_SIZE];
unsigned char iv[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};

int symm_crypt_init(void * sub_proc,void * para)
{
	int ret;
	// add youself's plugin init func here
    	struct init_struct init_para;
    	if(para==NULL)	 
		return -EINVAL;
    	void * struct_template = create_struct_template(&init_struct_desc);
    	if(struct_template == NULL)
		return -EINVAL;
	
   	ret=json_2_struct(para,&init_para,struct_template); 
    	if(ret<0)
		return -EINVAL;
    	free_struct_template(struct_template); 
	memset(passwd,0,DIGEST_SIZE);	   
	strncpy(passwd,init_para.passwd,DIGEST_SIZE);
	return 0;
}

int symm_crypt_start(void * sub_proc,void * para)
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
		if(!find_record_type(type))
		{
			printf("message format is not registered!\n");
			continue;
		}
		if(message_get_flag(recv_msg) &MSG_FLAG_CRYPT)
			proc_uncrypt_message(sub_proc,recv_msg);
		else
			proc_crypt_message(sub_proc,recv_msg);
	}

	return 0;
};

int proc_crypt_message(void * sub_proc,void * message)
{
        int i;
        int ret;
        sm4_context ctx;

        BYTE * blob;
        int blob_size;

        BYTE* bind_blob;
        int bind_blob_size;

        blob_size=message_get_blob(message,&blob);
        if(blob_size<=0)
                return -EINVAL;

	bind_blob_size=blob_size;

	bind_blob=malloc(bind_blob_size);
	if(bind_blob==NULL)
		return -ENOMEM;

	sm4_setkey_enc(&ctx,passwd);
	for(i=0;i<bind_blob_size;i+=16)
	{
		if(blob_size-i>=16)
			sm4_crypt_ecb(&ctx,1,16,blob+i,bind_blob+i);
	}	
	for(;i<blob_size;i++)
		bind_blob[i]=blob[i]^iv[i%16];		

        message_set_blob(message,bind_blob,bind_blob_size);
        message_set_flag(message,MSG_FLAG_CRYPT);

        sec_subject_sendmsg(sub_proc,message);
        return ret;
}

int proc_uncrypt_message(void * sub_proc,void * message)
{
        int i;
        int ret;
        sm4_context ctx;

        BYTE * blob;
        int blob_size;

        BYTE* bind_blob;
        int bind_blob_size;

        bind_blob_size=message_get_blob(message,&blob);
        if(bind_blob_size<=0)
                return -EINVAL;
	blob_size=bind_blob_size;

	blob=malloc(blob_size);
	if(blob==NULL)
		return -ENOMEM;

	sm4_setkey_dec(&ctx,passwd);
	for(i=0;i<bind_blob_size;i+=16)
	{
		if(blob_size-i>=16)
			sm4_crypt_ecb(&ctx,1,16,blob+i,bind_blob+i);
	}	
	for(;i<blob_size;i++)
		bind_blob[i]=blob[i]^iv[i%16];		

        message_set_blob(message,blob,blob_size);
	int flag=message_get_flag(message);
        message_set_flag(message,flag&(~MSG_FLAG_CRYPT));

        sec_subject_sendmsg(sub_proc,message);
        return ret;
}
