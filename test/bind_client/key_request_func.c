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
#include <tss/tss_structs.h>
#include <tss/tpm.h>

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
#include "../include/tesi_key.h"


#include "../cloud_config.h"
#include "main_proc_func.h"

int key_request_init(void * sub_proc,void * para)
{
	int ret;
	// add youself's plugin init func here
	return 0;
}

int key_request_start(void * sub_proc,void * para)
{
	int ret;
	void * recv_msg;
	int i;
	const char * type;
	int fd;

	enum key_state_type{
		NO_KEY,
		AIK_REQUEST,
		AIK_READY,
		BINDKEY_REQUEST,
		BINDKEY_READY,
		KEY_ERROR
	}; 

	enum key_state_type key_state=NO_KEY;
	struct key_request_cmd * key_req;
	int count;
	
	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	
	ret=proc_share_data_getvalue("uuid",local_uuid);
	ret=proc_share_data_getvalue("proc_name",proc_name);
	void * sendmsg;
	



	for(i=0;i<3000*1000;i++)
	{

		usleep(time_val.tv_usec);
		switch(key_state){
			case NO_KEY:

				fd=open("pubkey/AIK.pem",O_RDONLY);
				if(fd>0)
					key_state=AIK_READY;
				else
				{
					key_req=malloc(sizeof(struct key_request_cmd));
					if(key_req==NULL)
						return -EINVAL;		
					memcpy(key_req->machine_uuid,local_uuid,DIGEST_SIZE*2);
					key_req->proc_name=dup_str(proc_name,DIGEST_SIZE*2);
					key_req->keyusage=TPM_KEY_IDENTITY;
					key_req->keyflags=0;
					count=0;
					key_state=AIK_REQUEST;
					sendmsg=message_create("KREC",NULL);
					if(sendmsg==NULL)
						return -EINVAL;
					message_add_record(sendmsg,key_req);
					sec_subject_sendmsg(sub_proc,sendmsg);	
				}
				break;
			case AIK_REQUEST:
				fd=open("pubkey/AIK.pem",O_RDONLY);
				if(fd>0)
					key_state=AIK_READY;
				else
				{
					count++;
					if(count>1000)
					{
						printf("do not get AIK");
						key_state=NO_KEY;
					}	
				}
				break;
			case AIK_READY:
				fd=open("pubkey/bindpubkey.pem",O_RDONLY);
				if(fd>0)
					key_state=BINDKEY_READY;
				else
				{
					key_req=malloc(sizeof(struct key_request_cmd));
					if(key_req==NULL)
						return -EINVAL;		
					memcpy(key_req->machine_uuid,local_uuid,DIGEST_SIZE*2);
					key_req->proc_name=dup_str(proc_name,DIGEST_SIZE*2);
					key_req->keyusage=TPM_KEY_BIND;
					key_req->keyflags=0;
					count=0;
					key_state=BINDKEY_REQUEST;
					sendmsg=message_create("KREC",NULL);
					if(sendmsg==NULL)
						return -EINVAL;
					message_add_record(sendmsg,key_req);
					sec_subject_sendmsg(sub_proc,sendmsg);	
				}
				break;
			case BINDKEY_REQUEST:
				fd=open("pubkey/bindpubkey.pem",O_RDONLY);
				if(fd>0)
					key_state=BINDKEY_READY;
				else
				{
					count++;
					if(count>1000)
					{
						printf("do not get Bind key");
						key_state=AIK_READY;
					}	
				}
				break;
			case BINDKEY_READY:
				return 0;
			
			default:
				return -EINVAL;	
		
		}
	}
	return 0;
}
