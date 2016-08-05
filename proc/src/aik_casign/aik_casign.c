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
#include "../include/vm_policy.h"
#include "../include/connector.h"
#include "../include/logic_baselib.h"
#include "../include/connector.h"
#include "../include/sec_entity.h"
#include "../include/tesi.h"
#include "../include/main_proc_init.h"
#include "../include/tesi_key.h"
#include "../include/tesi_aik_struct.h"
#include "../include/valuename.h"
#include "../include/expand_define.h"

#include "aik_casign.h"

struct aik_proc_pointer
{
	RSA *  cakey;
	TSS_HKEY hCAKey;
};

int load_policy_pubek(char *pubek_name)
{
	struct vTPM_publickey *pubkey;
        BYTE digest[DIGEST_SIZE];
        char buffer[DIGEST_SIZE*2];
	int retval;
	int len;
	char filename[256];

	pubkey=malloc(sizeof(struct vTPM_publickey));
        if(pubkey==NULL)
        {
                return -ENOMEM;
        }
	snprintf(filename,DIGEST_SIZE*2,"%s.pem",pubek_name);
        memset(pubkey,0,sizeof(struct vTPM_publickey));
        calculate_sm3(pubek_name,digest);
	digest_to_uuid(digest,buffer);

        memcpy(pubkey->uuid,buffer,DIGEST_SIZE*2);
        pubkey->ispubek=1;
	len=sizeof(char)*strlen(pubek_name);
	// we must add the '\0' as the name's end
	pubkey->key_filename=(char *)malloc(len+1);
        memcpy(pubkey->key_filename,pubek_name,len+1);
	retval=AddPolicy(pubkey,"PUBK");
	ExportPolicy("PUBK");

	return retval;
}
int public_key_memdb_init()
{
	TSS_RESULT * result;
	int ret;
	int retval;
	char * pubek_dirname="pubek";
	char namebuf[512];
	DIR * pubek_dir;

	// open the pubek's dir
	pubek_dir=opendir(pubek_dirname);
	if(pubek_dir==NULL)
	{
		return -EINVAL;
	}
	struct dirent * dentry;

	while((dentry=readdir(pubek_dir))!=NULL)
	{
		if(dentry->d_type !=DT_REG)
			continue;
		// check if file's tail is string ".pem"
		int namelen=strlen(dentry->d_name);
		if(namelen<=4)
			continue;
		char * tail=dentry->d_name+namelen-4;
		if(strcmp(tail,".pem")!=0)
			continue;
		strcpy(namebuf,pubek_dirname);
		strcat(namebuf,"/");
		strncat(namebuf,dentry->d_name,256);

		retval=load_policy_pubek(namebuf);
		if(IS_ERR(retval))
			return retval;
		printf("load pubek %s succeed!\n",namebuf);
	}
	return 0;
}

int aik_casign_init(void * sub_proc,void * para)
{
	int ret;
	TSS_RESULT result;	
	char local_uuid[DIGEST_SIZE*2+1];
	
	struct aik_proc_pointer * aik_pointer;
//	main_pointer= kmalloc(sizeof(struct main_proc_pointer),GFP_KERNEL);
	aik_pointer= malloc(sizeof(struct aik_proc_pointer));
	if(aik_pointer==NULL)
		return -ENOMEM;
	memset(aik_pointer,0,sizeof(struct aik_proc_pointer));

	OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
	result=TESI_Local_Reload();
	if(result!=TSS_SUCCESS)
	{
		printf("open tpm error %d!\n",result);
		return -ENFILE;
	}

	public_key_memdb_init();
	
	ReadPrivKey(&(aik_pointer->cakey),"privkey/CA","my ca center");
	if(aik_pointer->cakey == NULL)
	{
		printf("read rsa private key failed!\n");
		return 0;
	}

	result=TESI_Local_GetPubKeyFromCA(&(aik_pointer->hCAKey),"cert/CA");
	if(result!=TSS_SUCCESS)
		return result;
//	TESI_Local_Fin();
	void * context;
	ret=sec_subject_getcontext(sub_proc,&context);
	if(ret<0)
		return ret;
	ret=sec_object_setpointer(context,aik_pointer);
	if(ret<0)
		return ret;
	return 0;
}

int aik_casign_start(void * sub_proc,void * para)
{
	int ret;
	void * recv_msg;
	int i;
	const char * type;

	printf("begin aik casign start!\n");

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
		if(strncmp(type,"FILN",4)==0)
		{
			proc_aik_casign(sub_proc,recv_msg);
		}
	}

	return 0;
};

int proc_aik_casign(void * sub_proc,void * recv_msg)
{
	TSS_RESULT result;
	TSS_HKEY 	hSignKey;
	TSS_HKEY	hAIKey, hCAKey;
	struct aik_cert_info certinfo;
	struct policyfile_req * reqdata;
	TCPA_IDENTITY_PROOF	identityProof;
	int ret;

	char local_uuid[DIGEST_SIZE*2+1];
	char proc_name[DIGEST_SIZE*2+1];
	struct aik_proc_pointer * aik_pointer;
	
	ret=proc_share_data_getvalue("uuid",local_uuid);
	ret=proc_share_data_getvalue("proc_name",proc_name);

	printf("begin aik casign!\n");
	char buffer[1024];
	char digest[DIGEST_SIZE];
	int blobsize=0;
	int fd;

	void * context;
	ret=sec_subject_getcontext(sub_proc,&context);
	if(ret<0)
		return ret;
	aik_pointer=sec_object_getpointer(context);
	if(aik_pointer==NULL)
		return -EINVAL;

	TESI_AIK_VerifyReq(aik_pointer->cakey,aik_pointer->hCAKey,"cert/aik",&hAIKey,&identityProof);
	struct ca_cert usercert;

	// read the req info from aik request package
	void * struct_template=create_struct_template(&aik_cert_info_desc);
	if(struct_template==NULL)
		return -EINVAL;
	blobsize=blob_2_struct(identityProof.labelArea,&certinfo,struct_template);
	if(blobsize!=identityProof.labelSize)
		return -EINVAL;

	// get the pubek
	struct vTPM_publickey * pubek;
	FindPolicy(certinfo.pubkey_uuid,"PUBK",&pubek);
	if(pubek==NULL)
	{
		printf("can't find pubek!\n");
		return -EINVAL;
	}
	char * pubek_name;
	pubek_name=dup_str(pubek->key_filename,128);
	pubek_name[strlen(pubek_name)-4]=0;
	printf("find pubek %s\n!",pubek_name);

//	free_struct_template(struct_template);

	// get the uuid of identity key and write it to user cert
	TESI_Local_WritePubKey(hAIKey,"identkey");

	calculate_sm3("identkey.pem",digest);
	digest_to_uuid(digest,certinfo.pubkey_uuid);

	printf(" get aik pubkey uuid %64s!\n",certinfo.pubkey_uuid);

//	struct_template=create_struct_template(ca_cert_desc);
	if(struct_template==NULL)
		return -EINVAL;
	// get the usercert's blob 
	blobsize=struct_2_blob(&certinfo,buffer,struct_template);
	free_struct_template(struct_template);	
	printf("create usercert succeed!\n");
	
		
	if (result = TESI_AIK_CreateAIKCert(hAIKey,aik_pointer->cakey,buffer,blobsize,pubek_name,"cert/active")) {
		printf("ca_create_credential %s", tss_err_string(result));
		free(pubek_name);
		return result;
	}
	printf("create active.req succeed!\n");
	free(pubek_name);

	reqdata=malloc(sizeof(struct policyfile_req));
	memset(reqdata,0,sizeof(struct policyfile_req));
	reqdata->filename=dup_str("cert/active.req",0);
	void * send_msg;
	send_msg=message_create("FILQ",recv_msg);
	message_add_record(send_msg,reqdata);
	sec_subject_sendmsg(sub_proc,send_msg);

	return 0;

}
