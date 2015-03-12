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

#include "cloud_config.h"
#include "main_proc_func.h"
#include "proc_config.h"

struct main_proc_pointer
{
	TSS_HKEY hAIKey;
};

int trust_manager_init(void * proc,void * para)
{
	int ret;
	TSS_RESULT result;	
	char local_uuid[DIGEST_SIZE*2+1];
	
	struct main_proc_pointer * main_pointer;
//	main_pointer= kmalloc(sizeof(struct main_proc_pointer),GFP_KERNEL);
//

	system("mkdir pubkey privkey cert");
	main_pointer= malloc(sizeof(struct main_proc_pointer));
	if(main_pointer==NULL)
		return -ENOMEM;
        ret=get_local_uuid(local_uuid);
        printf("this machine's local uuid is %s\n",local_uuid);
	proc_share_data_setvalue("uuid",local_uuid);
	proc_share_data_setvalue("proc_name",para);
	main_pointer->hAIKey=NULL;

	OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
	result=TESI_Local_ReloadWithAuth("ooo","sss");
	if(result!=TSS_SUCCESS)
	{
		printf("open tpm error %d!\n",result);
		return -ENFILE;
	}
        printf("open tpm success!\n");
	proc_share_data_setpointer(main_pointer);
	sec_subject_register_statelist(proc,main_state_list);
	return 0;
}



int wrapped_key_memdb_init()
{
	return 0;
}

int public_key_memdb_init()
{
	TSS_RESULT * result;
	int ret;
	result=TESI_Local_ReloadWithAuth("ooo","sss");
	if(result!=TSS_SUCCESS)
	{
		printf("reload tpm error %d!\n",result);
		return -ENFILE;
	}
	result=TESI_Local_GetPubEK("pubkey/pubek","ooo");
	if(result!=TSS_SUCCESS)
	{
		printf("get tpm pubek error %d!\n",result);
		return -ENFILE;
	}
	ret=load_policy_pubek("pubkey/pubek");
	return 0;
}

int vtpm_memdb_init()  // get the tpm information and init the vtpm database
{
	int retval;
	int ret;
	char * record_package;
	TSS_HKEY 		hSignKey;
	TSS_RESULT result;
	BYTE digest[DIGEST_SIZE];

	struct vTPM_info	*local_tpm;
	struct vTPM_wrappedkey	*local_signkey;
	struct vTPM_publickey   *local_signpubkey;
	char * keypass="kkk";

	local_tpm=malloc(sizeof(struct vTPM_info));
	if(local_tpm==NULL)
		return -ENOMEM;

	local_signkey=malloc(sizeof(struct vTPM_wrappedkey));
	if(local_signkey==NULL)
		return -ENOMEM;

	local_signpubkey=malloc(sizeof(struct vTPM_publickey));
	if(local_signpubkey==NULL)
		return -ENOMEM;

	// if it is the first time to exec it, we should create a sign key for controller.

	result=TESI_Local_Reload();

	if ( result != TSS_SUCCESS )
	{
		printf("TESI_Local_Load Err!\n");
		return result;
	}
		// create this vtpm's info struct
	
	char local_uuid[DIGEST_SIZE*2+1];
	
	ret=proc_share_data_getvalue("uuid",local_uuid);

	ret=create_physical_tpm_struct(local_tpm,local_uuid,"vtpm_manager","ooo","sss",NULL,NULL);
       	AddPolicy(local_tpm,"VM_T");
       	ExportPolicyToFile("lib/VM_T.lib","VM_T");

	printf("create local tpm info success!\n");
	TESI_Local_Fin();
	return 0;
}

int verify_aik_cert(void * message)
{
	printf("begin to verify the aik certs!\n");
}
