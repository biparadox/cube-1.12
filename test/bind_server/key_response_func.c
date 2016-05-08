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
#include "../include/tesi_key.h"
#include "../include/tesi_aik_struct.h"

#include "cloud_config.h"
#include "main_proc_func.h"

int proc_key_response(void * sub_proc,void * message);
int key_response_init(void * sub_proc,void * para)
{
	int ret;
	return 0;
}

int key_response_start(void * sub_proc,void * para)
{
	int ret;
	int retval;
	void * recv_msg;
	void * send_msg;
	void * context;
	int i;
	const char * type;

	printf("begin key response start!\n");

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
		if(strncmp(type,"KREC",4)==0)
		{
			proc_key_response(sub_proc,recv_msg);
		}
	}

	return 0;
};


int proc_key_response(void * sub_proc,void * message)
{
	struct policyfile_data * response_data;
	struct policyfile_data * response_cert;
	int ret;
	BYTE buf[2048];
	void * send_msg;
	void * send_msg2;


	struct key_request_cmd * key_req;

	printf("begin key response!\n");
	int blobsize=0;

	ret=message_get_record(message,&key_req,0);

	if(ret<0)
		return -EINVAL;
		
	if(key_req->keyusage == TPM_KEY_IDENTITY)
	{
		// bind_client request AIK			
		//  send aik file
		ret=build_filedata_struct(&response_data,"pubkey/AIK.pem");
		if(ret<0)
			return -EINVAL;
		send_msg=message_create("FILD",message);
		if(send_msg!=NULL)
		{
			message_add_record(send_msg,response_data);
			sec_subject_sendmsg(sub_proc,send_msg);
		}
		//  send aik cert file
		ret=build_filedata_struct(&response_cert,"cert/AIK.sda");
		if(ret<0)
			return -EINVAL;
		send_msg2=message_create("FILD",message);
		if(send_msg2!=NULL)
		{
			message_add_record(send_msg2,response_cert);
			sec_subject_sendmsg(sub_proc,send_msg2);
		}

	}
	else
		return -EINVAL;
	return 0;
}
