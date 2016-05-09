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
#include "../include/tesi_aik_struct.h"


#include "../cloud_config.h"
#include "main_proc_func.h"

int bindkey_verify()
{
	TSS_VALIDATION valdata;
	TSS_RESULT result;
	TSS_HKEY hAIKey;
	TSS_HKEY hBindPubKey;
	KEY_CERT * cert;
	BYTE digest[DIGEST_SIZE];

	result=TESI_Local_ReadPubKey(&hAIKey,"pubkey/AIK");
	if(result!=TSS_SUCCESS)
	{
		printf("Read AIK failed!\n");
		return result;
	}

	result=TESI_Local_VerifyValData(hAIKey,"cert/bindkey");
	if(result!=TSS_SUCCESS)
	{
		printf("verify bindkey failed!\n");
		return result;
	}
	cert=create_key_certify_struct("cert/bindkey",NULL,NULL);
	if(cert==NULL)	
		return -EINVAL;
	result=TESI_Local_ReadPubKey(&hBindPubKey,"pubkey/bindpubkey");
	if(result!=TSS_SUCCESS)
	{
		printf("Read bindkey failed!\n");
		return result;
	}
	
	result=TESI_Report_GetKeyDigest(hBindPubKey,digest);
	if ( result != TSS_SUCCESS )
	{
		printf( "TESI_Report_GetKeyDigest failed!\n");
		return result;
	}

	if(memcmp(digest,cert->pubkeydigest,20)!=0)
		return -EINVAL;

	return 0;
}

int aik_verify()
{
	int ret;
	BYTE buf[128];
	TESI_SIGN_DATA signdata;
	TSS_RESULT result;
	void * struct_template;
	struct  aik_cert_info server_info;
	BYTE digest[DIGEST_SIZE];
	ret=ReadSignDataFromFile(&signdata,"cert/AIK");
	if(ret<0)
		return -EIO;
	
	result=TESI_AIK_VerifySignData(&signdata,"cert/CA");
	if (result != TSS_SUCCESS) {
		printf("verify AIK data error!\n");
		return -EINVAL;
	}

	struct_template=create_struct_template(&aik_cert_info_desc);
	if(struct_template==NULL)
		return -EINVAL;

	ret=blob_2_struct(signdata.data,&server_info,struct_template);
	if(ret<0)
		return -EINVAL;

	if(strcmp(server_info.user_info.user_name,"bind_server")!=0)
	{
		printf("Wrong Server! Server is %s\n",server_info.user_info.user_name);
		return -EINVAL;
	}

	calculate_sm3("pubkey/AIK.pem",&digest);

	digest_to_uuid(digest,buf);

	if(strncmp(buf,server_info.pubkey_uuid,DIGEST_SIZE*2)!=0)
	{
		printf("Wrong Key!\n" );
		return -EINVAL;
	}
	
	return 0;
}

int key_request_init(void * sub_proc,void * para)
{
	int ret;
	// add youself's plugin init func here
	TSS_RESULT	result;
	result=TESI_Local_ReloadWithAuth("ooo","sss");
	if ( result != TSS_SUCCESS )
	{
		printf("TESI_Local_Load Err!\n",result);
		return result;
	}

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
		BINDKEY_VERIFIED,
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
				{
					key_state=AIK_READY;
					count=0;
				}
				else
				{
					close(fd);
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
					close(fd);
					count++;
					if(count>1000)
					{
						printf("do not get AIK");
						key_state=NO_KEY;
					}	
				}
				break;
			case AIK_READY:

				fd=open("cert/AIK.sda",O_RDONLY);
				if(fd<0)
				{
					count++;
					break;
				}
				else
				{
					close(fd);
					ret=aik_verify();
					if(ret<0)
					{
						remove("cert/AIK.sda");
						remove("pubkey/AIK.pem");
						key_state=NO_KEY;
						break;
					}
					remove("cert/bindkey.val");
					remove("pubkey/bindpubkey.pem");
					count=0;
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
					close(fd);
					count++;
					if(count>5000)
					{
						printf("do not get Bind key");
						key_state=AIK_READY;
					}	
				}
				break;
			case BINDKEY_READY:
				fd=open("cert/bindkey.val",O_RDONLY);
				if(fd<0)
				{
					count++;
					if(count>5000)
					{
						printf("do not get Bind key valdata");
						key_state=AIK_READY;
					}	
					break;
				}
				else
				{
					close(fd);
					ret=bindkey_verify();
					if(ret!=0)
					{
						remove("cert/bindkey.val");
						remove("pubkey/bindpubkey.pem");
						key_state=AIK_READY;
						break;
					}	
					
					key_state=BINDKEY_VERIFIED;
				}

				break;
			
			case BINDKEY_VERIFIED:
				ret=bind_pubkey_memdb_init();
				if(ret<0)
				{
					printf("load bindpubkey error %d!\n",ret);
				}
				
				return 0;
			default:
				return -EINVAL;	
		
		}
			
	}
	return 0;
}
