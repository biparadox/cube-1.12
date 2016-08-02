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
#include "session_msg.h"
#include "user_info.h"


#include "key_manage.h"

int bind_key_generate(char * aik_uuid)
{
	TSS_HKEY	hKey;
	TSS_HKEY	hAIKey;
	TSS_RESULT	result;

	char aik_file[DIGEST_SIZE*3];

	sprintf(aik_file,"privkey/%.64s",aik_uuid);
	result=TESI_Local_CreateBindKey(&hKey,NULL,"sss","kkk");
	if ( result != TSS_SUCCESS )
	{
		printf( "Create bind_key error!\n" );
		return result ;
	}

	TESI_Local_WriteKeyBlob(hKey,"privkey/bindkey");
	if ( result != TSS_SUCCESS )
	{
		printf( "Write bind key error!\n");
		return result;
	}
	TESI_Local_WritePubKey(hKey,"pubkey/bindpubkey");
	if ( result != TSS_SUCCESS )
	{
		printf( "Write bind pubkey error!\n");
		return result;
	}
	result=TESI_Local_ReadKeyBlob(&hAIKey,aik_file);
	if ( result != TSS_SUCCESS )
	{
		printf( "Read AIK failed!\n");
		return result;
	}
	
	result=TESI_Local_LoadKey(hKey,NULL,"kkk");
	if ( result != TSS_SUCCESS )
	{
		printf( "Load AIK failed!\n");
		return result;
	}
	result=TESI_Local_LoadKey(hAIKey,NULL,"kkk");
	if ( result != TSS_SUCCESS )
	{
		printf( "Load AIK failed!\n");
		return result;
	}
	result=TESI_Report_CertifyKey(hKey,hAIKey,"cert/bindkey");	
	if ( result != TSS_SUCCESS )
	{
		printf( "Certify bindkey failed!\n");
		return result;
	}
	
	return result;
}
int bindkey_verify(char * aik_uuid,char * bindval_uuid,char * bindkey_uuid)
{
	TSS_VALIDATION valdata;
	TSS_RESULT result;
	TSS_HKEY hAIKey;
	TSS_HKEY hBindPubKey;
	KEY_CERT * cert;
	BYTE digest[DIGEST_SIZE];

	char aik_file[DIGEST_SIZE*3];
	char bindkey_val[DIGEST_SIZE*3];
	char bindkey_file[DIGEST_SIZE*3];


	sprintf(bindkey_val,"cert/%.64s",bindval_uuid);
	sprintf(aik_file,"pubkey/%.64s",aik_uuid);
	sprintf(bindkey_file,"pubkey/%.64s",bindkey_uuid);

	result=TESI_Local_ReadPubKey(&hAIKey,aik_file);
	if(result!=TSS_SUCCESS)
	{
		printf("Read AIK failed!\n");
		return result;
	}

	result=TESI_Local_VerifyValData(hAIKey,bindkey_val);
	if(result!=TSS_SUCCESS)
	{
		printf("verify bindkey failed!\n");
		return result;
	}
	cert=create_key_certify_struct(bindkey_val,NULL,NULL);
	if(cert==NULL)	
		return -EINVAL;
	result=TESI_Local_ReadPubKey(&hBindPubKey,bindkey_file);
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

int aik_verify(char * user)
{
	int ret;
	BYTE buf[128];
	TESI_SIGN_DATA signdata;
	TSS_RESULT result;
	void * struct_template;
	struct  aik_cert_info server_info;
	struct node_key_list * key_list;
	BYTE digest[DIGEST_SIZE];

	BYTE filename[DIGEST_SIZE*2+DIGEST_SIZE];

	

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

	/*
	if(strcmp(server_info.user_info.user_name,"bind_server")!=0)
	{
		printf("Wrong Server! Server is %s\n",server_info.user_info.user_name);
		return -EINVAL;
	}
	*/

	calculate_sm3("pubkey/AIK.pem",&digest);

	digest_to_uuid(digest,buf);

	if(strncmp(buf,server_info.pubkey_uuid,DIGEST_SIZE*2)!=0)
	{
		printf("Wrong Key!\n" );
		return -EINVAL;
	}
	
	key_list=malloc(sizeof(struct node_key_list));
	if(key_list==NULL)
		return -ENOMEM;
	if(user!=NULL)
	{
		strncpy(user,server_info.user_info.user_name,DIGEST_SIZE);
	}

	return 0;
}

int trustfile_to_uuidname(char * filename, char * uuid)
{
	int ret;
	char uuidname[DIGEST_SIZE*2+16];
	char digest[DIGEST_SIZE];
	char tail[6];


	ret=calculate_sm3(filename,digest);
	if(ret<0)
		return ret;
	digest_to_uuid(digest,uuid);
	
	strcpy(tail,filename+strlen(filename)-4);
		
	if(strncmp(tail,".pem",4)==0)
	{
		sprintf(uuidname,"pubkey/%.64s.pem",uuid);
	}
	else if(strncmp(tail,".key",4)==0)
	{
		sprintf(uuidname,"privkey/%.64s.key",uuid);
	}
	else if(strncmp(tail,".sda",4)==0)
	{
		sprintf(uuidname,"cert/%.64s.sda",uuid);
	}
	else if(strncmp(tail,".val",4)==0)
	{
		sprintf(uuidname,"cert/%.64s.val",uuid);
	}
	else if(strncmp(tail,".val",4)==0)
	{
		sprintf(uuidname,"cert/%.64s.crt",uuid);
	}
	else
		return -EINVAL;
	ret=rename(filename,uuidname);
	return ret;	
	
}

int local_key_generate(void * sub_proc)
{
	struct node_key_list * local_keylist;
	struct node_key_list * pub_keylist;
	struct key_request_cmd * key_req;
	int ret;
	int fd;
	int i;
	int count;
	char uuidname[DIGEST_SIZE*2+16];
	enum local_key_state{
		NO_AIKEY,
		AIK_REQUEST,
		AIK_GENERATE,
		AIK_VERIFY,
		BINDKEY_GENERATE,
		BINDKEY_VERIFY,
		SIGNKEY_GENERATE,
		SIGNKEY_VERIFY,
		LOCAL_KEY_ERROR=0xffff
	}; 

	enum local_key_state key_state=NO_AIKEY;

	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	char proc_uuid[DIGEST_SIZE*2+1];
	BYTE digest[DIGEST_SIZE];
	char temp_uuid[DIGEST_SIZE*2];
	void * sendmsg;
	
	ret=proc_share_data_getvalue("uuid",local_uuid);
	ret=proc_share_data_getvalue("proc_name",proc_name);
	comp_proc_uuid(local_uuid,proc_name,proc_uuid);

	ret=FindPolicy(proc_uuid,"LKLD",&local_keylist);
	if((ret<0) || (local_keylist==NULL))
	{
		key_state=NO_AIKEY;
		local_keylist=malloc(sizeof(struct node_key_list));
		if(local_keylist==NULL)
			return -ENOMEM;
		memset(local_keylist,0,sizeof(struct node_key_list));
		memcpy(local_keylist->nodeuuid,proc_uuid,DIGEST_SIZE*2);
		memcpy(local_keylist->localuuid,local_uuid,DIGEST_SIZE*2);
		memcpy(local_keylist->nodename,proc_name,DIGEST_SIZE*2);
		local_keylist->isnodelocal=1;
		ret=AddPolicy(local_keylist,"LKLD");
		if(ret<0)
			return -EINVAL;		
		pub_keylist=malloc(sizeof(struct node_key_list));
		if(pub_keylist==NULL)
			return -ENOMEM;
		memset(pub_keylist,0,sizeof(struct node_key_list));
		memcpy(pub_keylist->nodeuuid,proc_uuid,DIGEST_SIZE*2);
		memcpy(pub_keylist->localuuid,local_uuid,DIGEST_SIZE*2);
		memcpy(pub_keylist->nodename,proc_name,DIGEST_SIZE*2);
		pub_keylist->isnodelocal=1;
		ret=AddPolicy(local_keylist,"NKLD");
		if(ret<0)
			return -EINVAL;		

	}
	else
	{
		ret=FindPolicy(proc_uuid,"NKLD",&pub_keylist);
		if(ret<0)
			return -EINVAL;
		
		if(local_keylist->nodeAIK[0]==0)
			key_state=AIK_REQUEST;
		else if(pub_keylist->nodeAIKSda[0]==0)
			key_state=AIK_GENERATE;
		else if(local_keylist->nodeBindKey[0]==0)
			key_state=AIK_VERIFY;
		else if(pub_keylist->nodeBindKeyVal[0]==0)
			key_state=BINDKEY_GENERATE;
		else if(local_keylist->nodeSignKey[0]==0)
			key_state=BINDKEY_VERIFY;
		else if(pub_keylist->nodeSignKeyVal[0]==0)
			key_state=SIGNKEY_GENERATE;
		else
		{
			key_state=SIGNKEY_VERIFY;
			return 0; 
		}
			
	}

	for(i=0;i<30*1000;i++)
	{

		usleep(time_val.tv_usec);
		switch(key_state){
			case NO_AIKEY:

				key_req=malloc(sizeof(struct key_request_cmd));
				if(key_req==NULL)
					return -EINVAL;		
				memcpy(key_req->machine_uuid,local_uuid,DIGEST_SIZE*2);
				memcpy(key_req->proc_name,"local",5);
				key_req->keyusage=TPM_KEY_IDENTITY;
				key_req->keyflags=0;
				count=0;
				key_state=AIK_REQUEST;
				sendmsg=message_create("KREC",NULL);
				if(sendmsg==NULL)
					return -EINVAL;
				message_add_record(sendmsg,key_req);
				sec_subject_sendmsg(sub_proc,sendmsg);	
				break;
			case AIK_REQUEST:
				fd=open("pubkey/AIK.pem",O_RDONLY);
				if(fd>0)
				{
					close(fd);
					key_state=AIK_GENERATE;
					count=0;
					fd=open("privkey/AIK.key",O_RDONLY);
					if(fd<0)
						return -EINVAL;
					close(fd);
					ret=calculate_sm3("privkey/AIK.key",digest);
					if(ret<0)
						return ret;
					digest_to_uuid(digest,local_keylist->nodeAIK);
					ret=calculate_sm3("pubkey/AIK.pem",digest);
					if(ret<0)
						return ret;
					digest_to_uuid(digest,pub_keylist->nodeAIK);
					
				}
				else
				{
					close(fd);
					count++;
					if(count>1000)
					{
						printf("do not get AIK");
						key_state=NO_AIKEY;
						remove("privkey/AIK.key");
						remove("pubkey/AIK.pem");
					}	
				}
				break;

			case AIK_GENERATE:

				fd=open("cert/AIK.sda",O_RDONLY);
				if(fd<0)
				{
					count++;
					if(count>1000)
					{
						remove("cert/AIK.sda");
						remove("pubkey/AIK.pem");
						remove("privkey/AIK.key");
						key_state=NO_AIKEY;
					}
					break;
				}
				else
				{
					close(fd);
					ret=aik_verify(local_keylist->username);
					if(ret<0)
					{
						remove("cert/AIK.sda");
						remove("pubkey/AIK.pem");
						remove("privkey/AIK.key");
						key_state=NO_AIKEY;
						break;
					}
					memcpy(pub_keylist->username,local_keylist->username,DIGEST_SIZE);
					ret=trustfile_to_uuidname("privkey/AIK.key",local_keylist->nodeAIK);
					if(ret<0)
						return ret;
					ret=trustfile_to_uuidname("pubkey/AIK.pem",pub_keylist->nodeAIK);
					if(ret<0)
						return ret;
					ret=trustfile_to_uuidname("cert/AIK.sda",pub_keylist->nodeAIKSda);
					if(ret<0)
					{
						return ret;
					}
					memcpy(local_keylist->nodeAIKSda,pub_keylist->nodeAIKSda,DIGEST_SIZE*2);
					
					ret=DelPolicy(local_keylist,"LKLD");	
					ret=AddPolicy(local_keylist,"LKLD");
					ret=ExportPolicy("LKLD");

					ret=DelPolicy(pub_keylist,"NKLD");	
					ret=AddPolicy(pub_keylist,"NKLD");
					ret=ExportPolicy("NKLD");
					remove("cert/bindkey.val");
					remove("pubkey/bindpubkey.pem");
					count=0;
					
					key_state=AIK_VERIFY;
					
				}
				break;

			case AIK_VERIFY:
				fd=open("pubkey/bindpubkey.pem",O_RDONLY);
				if(fd>0)
					key_state=BINDKEY_GENERATE;
				else
				{
					close(fd);
					ret=bind_key_generate(local_keylist->nodeAIK);
					if(ret<0)
						return ret;
				}
				break;
			case BINDKEY_GENERATE:
				fd=open("cert/bindkey.val",O_RDONLY);
				if(fd<0)
				{
					count++;
					if(count>5000)
					{
						printf("do not get Bind key valdata");
						key_state=AIK_GENERATE;
					}	
					break;
				}
				else
				{
					close(fd);
					ret=trustfile_to_uuidname("cert/bindkey.val",pub_keylist->nodeBindKeyVal);
					if(ret<0)
						return ret;
					ret=trustfile_to_uuidname("privkey/bindkey.key",local_keylist->nodeBindKey);
					if(ret<0)
						return ret;
					ret=trustfile_to_uuidname("pubkey/bindpubkey.pem",pub_keylist->nodeBindKey);
					if(ret<0)
					{
						remove("pubkey/bindpubkey.pem");
						return ret;
					}

					if(bindkey_verify(pub_keylist->nodeAIK,pub_keylist->nodeBindKeyVal,pub_keylist->nodeBindKey)!=0)
					{
						printf("bindkey verify failed!\n");
						return -EINVAL;
					}
					else
					{

						ret=DelPolicy(local_keylist,"LKLD");	
						ret=AddPolicy(local_keylist,"LKLD");
						ret=ExportPolicy("LKLD");

						ret=DelPolicy(pub_keylist,"NKLD");	
						ret=AddPolicy(pub_keylist,"NKLD");
						ret=ExportPolicy("NKLD");
					}
					
					key_state=BINDKEY_VERIFY;
				}

				break;
			
			case BINDKEY_VERIFY:
//				ret=bind_pubkey_memdb_init();
//				if(ret<0)
//				{
//					printf("load bindpubkey error %d!\n",ret);
//				}
				
				return 0;

			default:
				return -EINVAL;	
		
		}
	}
	return 0;

}

int local_pubkey_share(void * sub_proc)
{
	struct node_key_list * pub_keylist;
	int ret;
	int count;
	char uuidname[DIGEST_SIZE*2+16];
	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	char proc_uuid[DIGEST_SIZE*2+1];
	BYTE digest[DIGEST_SIZE];

	void * sendmsg;
	
	ret=proc_share_data_getvalue("uuid",local_uuid);
	ret=proc_share_data_getvalue("proc_name",proc_name);
	comp_proc_uuid(local_uuid,proc_name,proc_uuid);

	ret=FindPolicy(proc_uuid,"NKLD",&pub_keylist);
	if((ret<0) || (pub_keylist==NULL))
		return -EINVAL;
		
	sendmsg=message_create("NKLD",NULL);
	message_add_record(sendmsg,pub_keylist);
	
	sec_subject_sendmsg(sub_proc,sendmsg);
	
	
	void * new_msg;
	struct policyfile_data * reqdata;
	// share AIK
	sprintf(uuidname,"pubkey/%.64s.pem",pub_keylist->nodeAIK);
	ret=build_filedata_struct(&reqdata,uuidname);
	new_msg=message_create("FILD",NULL);
	if(new_msg!=NULL)
	{
		message_add_record(new_msg,reqdata);
		sec_subject_sendmsg(sub_proc,new_msg);
	}
	// share AIKsda
	sprintf(uuidname,"cert/%.64s.sda",pub_keylist->nodeAIKSda);
	ret=build_filedata_struct(&reqdata,uuidname);
	new_msg=message_create("FILD",NULL);
	if(new_msg!=NULL)
	{
		message_add_record(new_msg,reqdata);
		sec_subject_sendmsg(sub_proc,new_msg);
	}
	// share Bindkey
	sprintf(uuidname,"pubkey/%.64s.pem",pub_keylist->nodeBindKey);
	ret=build_filedata_struct(&reqdata,uuidname);
	new_msg=message_create("FILD",NULL);
	if(new_msg!=NULL)
	{
		message_add_record(new_msg,reqdata);
		sec_subject_sendmsg(sub_proc,new_msg);
	}
	// share Bindkeyval
	sprintf(uuidname,"cert/%.64s.val",pub_keylist->nodeBindKeyVal);
	ret=build_filedata_struct(&reqdata,uuidname);
	new_msg=message_create("FILD",NULL);
	if(new_msg!=NULL)
	{
		message_add_record(new_msg,reqdata);
		sec_subject_sendmsg(sub_proc,new_msg);
	}

	return 0;
}

int local_pubkey_request(void * sub_proc,char * user)
{
	struct node_key_list * pub_keylist;
	int ret;
	int count;
	char uuidname[DIGEST_SIZE*2+16];
	char proc_uuid[DIGEST_SIZE*2+1];
	BYTE digest[DIGEST_SIZE];

	void * sendmsg;


	ret=GetFirstPolicy(&pub_keylist,"NKLD");
	if(ret<0)
		return -EINVAL;
	while(pub_keylist!=NULL)
	{
		if(strncmp(pub_keylist->username,user,DIGEST_SIZE)==0)
		{
			printf("user %s's pubkey is already getten!\n",user);
			return 0;
		}
		ret=GetNextPolicy(&pub_keylist,"NKLD");
		if(ret<0)
			return -EINVAL;
	}	
	
	struct key_request_cmd * key_req;
	key_req=malloc(sizeof(struct key_request_cmd));
	if(key_req==NULL)
		return -ENOMEM;
	memset(key_req,0,sizeof(struct key_request_cmd));
	strncpy(key_req->user_name,user,DIGEST_SIZE);	

	sendmsg=message_create("KREC",NULL);
	message_add_record(sendmsg,key_req);
	
	sec_subject_sendmsg(sub_proc,sendmsg);
}

int key_manage_init(void * sub_proc,void * para)
{
	int ret;
	// add youself's plugin init func here
	TSS_RESULT	result;
//	result=TESI_Local_ReloadWithAuth("ooo","sss");
//	if ( result != TSS_SUCCESS )
//	{
//		printf("TESI_Local_Load Err!\n",result);
//		return result;
//	}

	return 0;
}

int key_manage_start(void * sub_proc,void * para)
{
	int ret;
	void * recv_msg;
	int i;
	const char * type;
	int fd;

	enum key_state_type{
		NO_KEY,
		KEY_GENERATE,
		KEY_SHARED,
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
	
	ret=local_key_generate(sub_proc);	
	if(ret<0)
		return ret;
	key_state=KEY_GENERATE;
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

		switch(key_state){
			case KEY_GENERATE:
				if(strncmp(type,"ACKI",4)==0)
				{
					ret=local_pubkey_share(sub_proc);
					if(ret<0)
						return ret;
					key_state=KEY_SHARED;
				}
				break;
			case KEY_SHARED:
				if(strncmp(type,"LOGI",4)==0)
				{
					struct login_info * user_info;
					int j=0;
					
					ret=message_get_record(recv_msg,&user_info,j++);
					
					while(user_info!=NULL)
					{
						ret=local_pubkey_request(sub_proc,user_info->user);
						if(ret<0)
							break;
						ret=message_get_record(recv_msg,&user_info,j++);
						if(ret<0)
							break;
					}
					sec_subject_sendmsg(sub_proc,recv_msg);
				}
				else if(strncmp(type,"NKLD",4)==0)
				{
					struct node_key_list * pub_keylist;
					int j=0;
					
					ret=message_get_record(recv_msg,&pub_keylist,j++);
					
					if(pub_keylist!=NULL)
					{
						AddPolicy(pub_keylist,"NKLD");
					}
					ExportPolicy("NKLD");
				}
				
				break;
			default:
				break;
		}
	}
	return 0;
}
