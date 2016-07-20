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
#include "../include/vmlist.h"
#include "../include/vtpm_struct.h"
#include "../include/vm_policy.h"
#include "../include/connector.h"
#include "../include/logic_baselib.h"
#include "../include/connector.h"
#include "../include/sec_entity.h"
#include "../include/tesi.h"
#include "../include/main_proc_init.h"
#include "../include/tesi_aik_struct.h"
#include "../include/valuename.h"
#include "../include/expand_define.h"

#include "cloud_config.h"
#include "local_func.h"
#include "main_proc_func.h"
#include "aik_casign_func.h"

struct caverify_proc_pointer
{
	RSA *  cakey;
	TSS_HKEY hCAKey;
};

int ca_verify_init(void * sub_proc,void * para)
{
	int ret;
	TSS_RESULT result;	
	char local_uuid[DIGEST_SIZE*2+1];
	
	struct caverify_proc_pointer * caverify_pointer;
//	main_pointer= kmalloc(sizeof(struct main_proc_pointer),GFP_KERNEL);
	caverify_pointer= malloc(sizeof(struct caverify_proc_pointer));
	if(caverify_pointer==NULL)
		return -ENOMEM;
	memset(caverify_pointer,0,sizeof(struct caverify_proc_pointer));

	OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
	result=TESI_Local_Reload();
	if(result!=TSS_SUCCESS)
	{
		printf("open tpm error %d!\n",result);
		return -ENFILE;
	}

	ReadPrivKey(&(caverify_pointer->cakey),"privkey/CA","my ca center");
	if(caverify_pointer->cakey == NULL)
	{
		printf("read rsa private key failed!\n");
		return 0;
	}

	result=TESI_Local_GetPubKeyFromCA(&(caverify_pointer->hCAKey),"cert/CA");
	if(result!=TSS_SUCCESS)
		return result;
//	TESI_Local_Fin();
	void * context;
	ret=sec_subject_getcontext(sub_proc,&context);
	if(ret<0)
		return ret;
	ret=sec_object_setpointer(context,caverify_pointer);
	if(ret<0)
		return ret;
	return 0;
}

int ca_verify_start(void * sub_proc,void * para)
{
	int ret;
	void * recv_msg;
	int i;
	const char * type;


	for(i=0;i<300*1000;i++)
	{
		usleep(time_val.tv_usec);
		ret=sec_subject_recvmsg(sub_proc,&recv_msg);
		if(ret<0)
			continue;
		if(recv_msg==NULL)
			continue;
		type=message_get_recordtype(recv_msg);
		if(type==NULL)
			continue;
		else if(strncmp(type,"LOGC",4)==0)
		{
			proc_ca_verify(sub_proc,recv_msg);
		}
	}

	return 0;
};

int proc_ca_verify(void * sub_proc,void * message)
{
	printf("begin ca verify!\n");
	struct message_box * msg_box=message;
	MESSAGE_HEAD * message_head;
	struct connect_login * login_info;
	void * pointer=*test_login;
	int retval;
	void *(*fn)(char * username,char * passwd)=pointer;
	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	
	retval=proc_share_data_getvalue("uuid",local_uuid);
	retval=proc_share_data_getvalue("proc_name",proc_name);

	retval=message_get_record(msg_box,&login_info,0);	
	if(retval<0)
		return -EINVAL;
	if(login_info==NULL)
		return -EINVAL;

	struct connect_return  * return_data;
	return_data=fn(login_info->user,login_info->passwd);
		
	if((return_data==NULL) || IS_ERR(return_data))
		return -EINVAL;

	struct message_box * new_msg;
	new_msg=message_create("RETC",message);
	message_add_record(new_msg,return_data);
	sec_subject_sendmsg(sub_proc,new_msg);

	return retval;

}
