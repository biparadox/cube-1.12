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

#include "aik_client.h"

int print_error(char * str, int result)
{
	printf("%s %s",str,tss_err_string(result));
}

struct aik_proc_pointer
{
	TSS_HKEY hAIKey;
	TSS_HKEY hSignKey;
	TESI_SIGN_DATA * aik_cert;
};

int aik_client_init(void * sub_proc,void * para)
{
	int ret;
	TSS_RESULT result;	
	char local_uuid[DIGEST_SIZE*2+1];
	
	struct aik_proc_pointer * aik_pointer;
	void * context;
//	main_pointer= kmalloc(sizeof(struct main_proc_pointer),GFP_KERNEL);
	aik_pointer= malloc(sizeof(struct aik_proc_pointer));
	if(aik_pointer==NULL)
		return -ENOMEM;
	memset(aik_pointer,0,sizeof(struct aik_proc_pointer));


//	result=TESI_Local_ReloadWithAuth("ooo","sss");
//	if(result!=TSS_SUCCESS)
//	{
//		printf("open tpm error %d!\n",result);
//		return -ENFILE;
//	}
	result= TESI_Local_GetPubEK("pubkey/pubek","ooo");
	if(result!=TSS_SUCCESS)
	{
		printf("get pubek error %d!\n",result);
		return -EIO;
	}
	ret=sec_subject_getcontext(sub_proc,&context);
	if(ret<0)
		return ret;
	ret=sec_object_setpointer(context,aik_pointer);
	if(ret<0)
		return ret;
	return 0;
}

int aik_client_start(void * sub_proc,void * para)
{
	int ret;
	int retval;
	void * recv_msg;
	void * send_msg;
	void * context;
	int i;
	const char * type;

	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	
	ret=proc_share_data_getvalue("uuid",local_uuid);
	ret=proc_share_data_getvalue("proc_name",proc_name);

	printf("begin aik process start!\n");

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
		{
			message_free(recv_msg);
			continue;
		}
		if(strncmp(type,"SYNI",4)==0)
		{
			proc_aik_request(sub_proc,recv_msg);
		}
		else if(strncmp(type,"KREC",4)==0)
		{
			proc_aik_request(sub_proc,recv_msg);
		}
		else if(strncmp(type,"FILN",4)==0)
		{
			proc_aik_activate(sub_proc,recv_msg);
		}
	}

	return 0;
};


int proc_aik_request(void * sub_proc,void * message)
{
	TSS_RESULT result;
	TSS_HKEY 	hSignKey;
	TSS_HKEY	hAIKey, hCAKey;
	struct aik_cert_info reqinfo;
//	struct policyfile_data * reqdata;
	struct policyfile_req * reqdata;
	int ret;
	struct aik_user_info * user_info;
	BYTE buf[1024];

	ret=GetFirstPolicy(&user_info,"USRI");
	if(ret<0)
		return -EINVAL;

	memcpy(&reqinfo.user_info,user_info,sizeof(struct aik_user_info));

/*
	BYTE		*labelString = "UserA";
	UINT32		labelLen = strlen(labelString) + 1;
*/
	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	
	ret=proc_share_data_getvalue("uuid",local_uuid);
	ret=proc_share_data_getvalue("proc_name",proc_name);

	printf("begin aik request!\n");
	char buffer[1024];
	char digest[DIGEST_SIZE];
	int blobsize=0;
	int fd;
	// create a signkey and write its key in localsignkey.key, write its pubkey in localsignkey.pem
	result=TESI_Local_ReloadWithAuth("ooo","sss");

	calculate_sm3("pubkey/pubek.pem",digest);
	digest_to_uuid(digest,reqinfo.pubkey_uuid);
	get_local_uuid(reqinfo.machine_uuid);
	
	// create info blob
	void * struct_template=create_struct_template(&aik_cert_info_desc);
	if(struct_template==NULL)
		return -EINVAL;
	blobsize=struct_2_blob(&reqinfo,buffer,struct_template);

	// Load the CA Key
	result=TESI_Local_GetPubKeyFromCA(&hCAKey,"cert/CA");
	if (result != TSS_SUCCESS) {
		printf("Get pubkey error %s!\n", tss_err_string(result));
		exit(result);
	}
	
	TESI_AIK_CreateIdentKey(&hAIKey,NULL,"sss","kkk"); 
	if (result != TSS_SUCCESS) {
		printf("Create AIK error %s!\n", tss_err_string(result));
		exit(result);
	}

	result = TESI_AIK_GenerateReq(hCAKey,blobsize,buffer,hAIKey,"cert/aik");
	if (result != TSS_SUCCESS){
		printf("Generate aik failed%s!\n",tss_err_string(result));
		exit(result);
	}
	TESI_Local_WriteKeyBlob(hAIKey,"privkey/AIK");

//	ret=build_filedata_struct(&reqdata,"cert/aik.req");
	reqdata=malloc(sizeof(struct policyfile_req));
	memset(reqdata,0,sizeof(struct policyfile_req));
	reqdata->filename=dup_str("cert/aik.req",0);

	void * send_msg;
	send_msg=message_create("FILQ",message);
	if(send_msg!=NULL)
	{
		message_add_record(send_msg,reqdata);
		sec_subject_sendmsg(sub_proc,send_msg);
	}
	return 0;
}

int proc_aik_activate(void * sub_proc,void * message)
{
	printf("begin aik activate!\n");
	TSS_RESULT	result;
	TSS_HKEY	hAIKey, hCAKey;
	
	TESI_SIGN_DATA signdata;

	int fd;
	int retval;
	int blobsize=0;
	struct policyfile_data * reqdata;
	struct aik_cert_info cert_info;


	result=TESI_Local_ReadKeyBlob(&hAIKey,"privkey/AIK");
	if ( result != TSS_SUCCESS )
	{
		print_error("TESI_Local_ReadKeyBlob Err!\n",result);
		return result;
	}

	result=TESI_Local_LoadKey(hAIKey,NULL,"kkk");
	if ( result != TSS_SUCCESS )
	{
		print_error("TESI_Local_LoadKey Err!\n",result);
		return result;
	}

//	retval=get_filedata_from_message(message);
//	if(retval<0)
//		return -EINVAL;
//	printf("get file succeed!\n");

	result=TESI_AIK_Activate(hAIKey,"cert/active",&signdata);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		exit(result);
	}
	// Load the CA Key
	result=TESI_Local_GetPubKeyFromCA(&hCAKey,"cert/CA");
	if (result != TSS_SUCCESS) {
		print_error("Get pubkey error!\n", result);
		exit(result);
	}
	
	// write the AIK and aipubkey

	result=TESI_Local_WriteKeyBlob(hAIKey,"privkey/AIK");
	if (result != TSS_SUCCESS) {
		print_error("store aik data error!\n", result);
		exit(result);
	}
	result=TESI_Local_WritePubKey(hAIKey,"pubkey/AIK");
	if (result != TSS_SUCCESS) {
		print_error("store aik data error!\n", result);
		exit(result);
	}

	// verify the CA signed cert
	result=TESI_AIK_VerifySignData(&signdata,"cert/CA");
	if (result != TSS_SUCCESS) {
		print_error("verify data error!\n", result);
		exit(result);
	}

	// get the content of the CA signed cert

	// read the req info from aik request package
	void * struct_template=create_struct_template(&aik_cert_info_desc);
	if(struct_template==NULL)
		return -EINVAL;
	blobsize=blob_2_struct(signdata.data,&cert_info,struct_template);
	if(blobsize!=signdata.datalen)
		return -EINVAL;

	WriteSignDataToFile(&signdata,"cert/AIK");

	free_struct_template(struct_template);

	return 0;
}
