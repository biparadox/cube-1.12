#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/extern_defno.h"
#include "../include/extern_struct.h"
#include "../include/extern_struct_desc.h"
#include "../include/message_struct.h"
#include "../include/message_struct_desc.h" 
#include "../include/connector.h"
#include "../include/logic_baselib.h"
#include "../include/policy_ui.h"
#include "../include/vm_policy.h"
#include "../include/vm_policy_desc.h"
#include "../include/vmlist.h"
#include "../include/vmlist_desc.h"
#include "../include/vtpm_struct.h"
#include "../include/vtpm_desc.h"
#include "../include/tesi.h"
#include "../include/openstack_trust_lib.h"
#include "vtpm_manager_func.h"

#include "cloud_config.h"

// vtpm_manager:
// memdb: vtpm_info.lib  "VM_T"   
//        blob_key.lib   "BLBK"
//        public_key.lib "PUBK"     

extern char local_uuid[DIGEST_SIZE*2];
extern char * proc_name;
extern char * swtpm_path;

int vtpm_info_memdb_init()
{
	int retval;
	char * record_package;
	TSS_HKEY 		hSignKey;
	TSS_RESULT result;
	BYTE digest[DIGEST_SIZE];

	struct vTPM_info	*local_tpm;
	struct vTPM_wrappedkey	*local_signkey;
	struct vTPM_publickey   *local_signpubkey;
	char * keypass="kkk";
	char * signkeyname="key/localsignkey";
	char tempkeyname[40];
	char temppubkeyname[40];

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

	result=TESI_Local_CreateSignKey(&hSignKey,(TSS_HKEY)NULL,"sss",keypass);
	if(result == TSS_SUCCESS)
		printf("Create SignKey SUCCEED!\n");

	// we write the sign key blob and the public sign key
	TESI_Local_WriteKeyBlob(hSignKey,signkeyname);
	TESI_Local_WritePubKey(hSignKey,signkeyname);
	
	strcpy(tempkeyname,signkeyname);
	strcat(tempkeyname,".key");
	strcpy(temppubkeyname,signkeyname);
	strcat(temppubkeyname,".pem");
	// create this tpm's signkey struct
	create_blobkey_struct(local_signkey,NULL,local_uuid,"kkk",tempkeyname);
	AddPolicy(local_signkey,"BLBK");
       	ExportPolicyToFile("lib/BLBK.lib","BLBK");

	// create this tpm's sign pubkey struct
	create_pubkey_struct(local_signpubkey,local_signkey->uuid,local_uuid,temppubkeyname);
       	AddPolicy(local_signpubkey,"PUBK");
    	ExportPolicyToFile("lib/PUBK.lib","PUBK");
		
		// create this vtpm's info struct

	create_physical_tpm_struct(local_tpm,local_uuid,"vtpm_manager","ooo","sss",local_signkey->uuid,local_signpubkey->uuid);
       	AddPolicy(local_tpm,"VM_T");
       	ExportPolicyToFile("lib/VM_T.lib","VM_T");

	printf("create local tpm info success!\n");
	proc_share_data_setstate(PROC_LOCAL_LOADLOCALTPMINFO);

	TESI_Local_Fin();
	return 0;
}

int blob_key_memdb_init()
{
	int retval;
	char * record_package;

	return 0;
}

int public_key_memdb_init()
{
	int retval;
	char * record_package;

	return 0;
}

int get_vtpm_port()
{
	int startno=14001;
	struct vTPM_info * vtpm;
	vtpm=GetFirstPolicy("VM_T");
	while(vtpm!=NULL)
	{
		if(vtpm->port>startno)
			startno=vtpm->port+2;
		vtpm=GetNextPolicy("VM_T");
	}
	return startno;
}


int process_vm_message(void * message_box,void * trust_conn)
{
	MESSAGE_HEAD * message_head;
	struct vm_info * vm;
	struct vTPM_info * vtpm;
	struct vTPM_wrappedkey	* vtpm_signkey;
	struct vTPM_publickey   * vtpm_pubek;
	struct vTPM_publickey   * vtpm_signpubkey;
	struct keyfile_data     * key_data;
	int retval;
	int i;

	
	char *newargv[10];
	char *newenv[10];
	char argbuf[10][128];
	char envbuf[10][128];


	vm=malloc(sizeof(struct vm_info));
	if(vm==NULL)
		return -ENOMEM;

	vtpm=malloc(sizeof(struct vTPM_info));
	if(vtpm==NULL)
		return -ENOMEM;

	vtpm_signkey=malloc(sizeof(struct vTPM_wrappedkey));
	if(vtpm_signkey==NULL)
		return -ENOMEM;


	vtpm_pubek=malloc(sizeof(struct vTPM_publickey));
	if(vtpm_pubek==NULL)
		return -ENOMEM;

	vtpm_signpubkey=malloc(sizeof(struct vTPM_publickey));
	if(vtpm_signpubkey==NULL)
		return -ENOMEM;

	message_head=get_message_head(message_box);

	if(strncmp(message_head->record_type,"VM_I",4)!=0)
	{
		return -EINVAL;
	}
	int vtpm_port;
		// monitor send a new vm message
	retval=load_message_record(message_box,vm);
	if(retval<0)
		return retval;
	printf("receive trust server 's VM_I message, vm is %s platform is %s!\n",vm->uuid,vm->platform_uuid);

	// program receive a vtpm request
	set_channel_extern_state(trust_conn,CHANNEL_LOCAL_VTPM_REQ);

	vtpm_port=get_vtpm_port();
	printf("get vtpm port %d!\n",vtpm_port);
		
	//create environment variables

	memset(newargv,0,sizeof(char *)*10);
	memset(newenv,0,sizeof(char *)*10);
	sprintf(envbuf[0],"TPM_SERVER_PORT=%d",vtpm_port);
	sprintf(envbuf[1],"TPM_SERVER_NAME=127.0.0.1");
	sprintf(envbuf[2],"TPM_PORT=%d",vtpm_port);
	sprintf(envbuf[3],"TPM_PATH=%s/tpmdata/%d",swtpm_path,vtpm_port);
	newenv[0]=envbuf[0];
	newenv[1]=envbuf[1];
	newenv[2]=envbuf[2];
	newenv[3]=envbuf[3];
	sprintf(argbuf[0],"&>>tpm%d.log",vtpm_port);
	newargv[1]=argbuf[0];
	char cmd[128];
	char buf[128];

	// create new vtpm's dir
	sprintf(cmd,"./tpm_mkdir %d",vtpm_port);
	system(cmd);
	int server_pid;
	server_pid=fork();
	if(server_pid==0)
	{
		//child process run tpm_server
		sprintf(cmd,"%s/tpm/tpm_server",swtpm_path);
		execve(cmd,newargv,newenv);
	}
	// main process
	printf("process %d run tpm_server!\n",server_pid);

	sleep(1);
	set_channel_extern_state(trust_conn,CHANNEL_LOCAL_VTPM_START);
	// run tpm_init 
	sprintf(cmd,"./tpm_init_script %d",vtpm_port); 
	system(cmd);
	// run tpmbios 
	sprintf(cmd,"./tpmbios_script %d",vtpm_port); 
	system(cmd);

	// kill tpm server
	sprintf(cmd,"kill -9 %d",server_pid); 
	system(cmd);
	sleep(1);
	// run tpm server again
	server_pid=fork();

	if(server_pid==0)
	{
		//child process run tpm_server
		sprintf(cmd,"%s/tpm/tpm_server",swtpm_path);
		execve(cmd,newargv,newenv);
	}
	printf("process %d run tpm_server!\n",server_pid);

	usleep(100*1000);
	// run tpmbios 
	set_channel_extern_state(trust_conn,CHANNEL_LOCAL_VTPM_INIT);
	sprintf(cmd,"./tpmbios_script %d",vtpm_port); 
	system(cmd);

	// create signkey for this vtpm
	sprintf(cmd,"./tpm_creatsignkey %d",vtpm_port); 
	system(cmd);

	// create this vtpm's pubek struct
	create_pubkey_struct(vtpm_pubek,NULL,vm->uuid,"pubek.pem");

      	AddPolicy(vtpm_pubek,"PUBK");
       	ExportPolicyToFile("lib/PUBK.lib","PUBK");

	// create this vtpm's signkey struct
	sprintf(buf,"%d.key",vtpm_port);
	create_blobkey_struct(vtpm_signkey,NULL,vm->uuid,"kkk",buf);
	AddPolicy(vtpm_signkey,"BLBK");
       	ExportPolicyToFile("lib/BLBK.lib","BLBK");

	// create this vtpm's sign pubkey struct
	sprintf(buf,"%d.pem",vtpm_port);
	create_pubkey_struct(vtpm_signpubkey,vtpm_signkey->uuid,vm->uuid,buf);
       	AddPolicy(vtpm_signpubkey,"PUBK");
    	ExportPolicyToFile("lib/PUBK.lib","PUBK");
	
	// create this vtpm's info struct

	create_vtpm_struct(vtpm,vm,"ooo","sss",vtpm_signkey->uuid,vtpm_signpubkey->uuid);
	vtpm->port=vtpm_port;
       	AddPolicy(vtpm,"VM_T");
       	ExportPolicyToFile("lib/VM_T.lib","VM_T");
       	return 0;
}
