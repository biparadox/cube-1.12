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
#include "../include/valuename.h"
#include "../include/message_struct.h"
#include "../include/message_struct_desc.h"
#include "../include/vmlist.h"
#include "../include/vm_policy.h"
#include "../include/connector.h"
#include "../include/logic_baselib.h"
#include "../include/connector.h"
#include "../include/sec_entity.h"
#include "../include/tesi.h"
#include "../include/main_proc_init.h"

#include "main_proc_func.h"

int test_bind_init()
{
	int ret;
	return 0;
}
int bind_pubkey_memdb_init(char * type, void * para)
{
	int ret;
	char * bindpubkeyname="pubkey/bindpubkey";
	struct vTPM_publickey	*local_bindpubkey;

	local_bindpubkey=malloc(sizeof(struct vTPM_publickey));
	if(local_bindpubkey==NULL)
		return -ENOMEM;

	ret=create_pubkey_struct(local_bindpubkey,NULL,NULL,bindpubkeyname);	
	if(ret<0)
		return ret;

	AddPolicy(local_bindpubkey,"PUBK");
       	ExportPolicy("PUBK");
	return 0;
}
int vtpm_memdb_init(char * type,void * para)  // get the tpm information and init the vtpm database
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
