/*************************************************
*************************************************/

#ifndef USER_MODE

#include <asm/uaccess.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/sched.h>

#else


#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "../include/kernel_comp.h"
#include "../include/list.h"
#include "../include/attrlist.h"

#endif

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/extern_struct.h"
#include "../include/extern_interface.h"
#include "../include/extern_struct_desc.h"
#include "../include/extern_defno.h"
#include "../include/crypto_func.h"
#include "../include/logic_baselib.h"
#include "../include/vmlist.h"
#include "../include/vtpm_struct.h"
#include "../include/vtpm_desc.h"
#include "../include/tesi_key.h"
#include "../include/tesi_key_desc.h"

#include "logic_compare.h"
#define DIGEST_SIZE 32

int create_physical_tpm_struct(struct vTPM_info * local_tpm,char * local_uuid,char * ownername,char * ownerpass,char * srkpass,
		char * signkey_uuid,char * pubkey_uuid)
{
	memset(local_tpm,0,sizeof(struct vTPM_info));
	memcpy(local_tpm->uuid,local_uuid,strlen(local_uuid));
	local_tpm->ownername=dup_str(ownername,0);
	local_tpm->tpm_type=PHYSICAL_TPM;
	local_tpm->ownerpass=dup_str(ownerpass,0);
	local_tpm->srkpass=dup_str(srkpass,0);

	if(signkey_uuid != NULL)
	{	
		local_tpm->wrappedkeynum=1;
		local_tpm->wrapkey_uuid=kmalloc(sizeof(char *)*local_tpm->wrappedkeynum,GFP_KERNEL);
		local_tpm->wrapkey_uuid[0]=dup_str(signkey_uuid,DIGEST_SIZE*2);
	}
	if(pubkey_uuid !=NULL)
	{
		local_tpm->pubkeynum=1;
		local_tpm->pubkey_uuid=malloc(sizeof(char *)*local_tpm->pubkeynum);
		local_tpm->pubkey_uuid[0]=dup_str(pubkey_uuid,DIGEST_SIZE*2);
	}
	return 0;
}

int build_empty_physical_tpm(struct vTPM_info * local_tpm,char * local_uuid,char * ownername)
{
	int copylen;
	memset(local_tpm,0,sizeof(struct vTPM_info));
	copylen=strlen(local_uuid)+1;
	if(copylen>DIGEST_SIZE*2)
		copylen=DIGEST_SIZE*2;
	strncpy(local_tpm->uuid,local_uuid,copylen);
	local_tpm->ownername=dup_str(ownername,0);
	local_tpm->tpm_type=PHYSICAL_TPM;
	return 0;
}
int add_pubek_to_tpm(struct vTPM_info * tpm, char * key_uuid)
{
	int copylen;
	if((tpm==NULL)||IS_ERR(tpm))
		return -EINVAL;
	if((key_uuid==NULL)||IS_ERR(key_uuid))
		return -EINVAL;

	copylen=strlen(key_uuid)+1;
	if(copylen>DIGEST_SIZE*2)
		copylen=DIGEST_SIZE*2;
	strncpy(tpm->pubEK_uuid,key_uuid,copylen);
	return 0;
}


int add_wrapkey_to_tpm(struct vTPM_info * tpm, char * key_uuid)
{
	BYTE * buffer;
	if((tpm==NULL)||IS_ERR(tpm))
		return -EINVAL;
	if((key_uuid==NULL)||IS_ERR(key_uuid))
		return -EINVAL;
	tpm->wrappedkeynum++;
	if(tpm->wrappedkeynum==1)
	{
		tpm->wrapkey_uuid=kmalloc(sizeof(char *)*tpm->wrappedkeynum,GFP_KERNEL);
		tpm->wrapkey_uuid[0]=dup_str(key_uuid,DIGEST_SIZE*2);
		
	}
	else
	{
		buffer=kmalloc(sizeof(char *)*tpm->wrappedkeynum,GFP_KERNEL);
		memcpy(buffer,tpm->wrapkey_uuid,sizeof(char *)*(tpm->wrappedkeynum-1));
		kfree(tpm->wrapkey_uuid);
		tpm->wrapkey_uuid=buffer;
		tpm->wrapkey_uuid[tpm->wrappedkeynum-1]=dup_str(key_uuid,DIGEST_SIZE*2);
	}
	return 0;
}

int add_pubkey_to_tpm(struct vTPM_info * tpm, char * key_uuid)
{
	BYTE * buffer;
	if((tpm==NULL)||IS_ERR(tpm))
		return -EINVAL;
	if((key_uuid==NULL)||IS_ERR(key_uuid))
		return -EINVAL;
	tpm->pubkeynum++;
	if(tpm->pubkeynum==1)
	{
		tpm->pubkey_uuid=kmalloc(sizeof(char *)*tpm->pubkeynum,GFP_KERNEL);
		tpm->pubkey_uuid[0]=dup_str(key_uuid,DIGEST_SIZE*2);
		
	}
	else
	{
		buffer=kmalloc(sizeof(char *)*tpm->pubkeynum,GFP_KERNEL);
		memcpy(buffer,tpm->pubkey_uuid,sizeof(char *)*(tpm->pubkeynum-1));
		kfree(tpm->pubkey_uuid);
		tpm->pubkey_uuid=buffer;
		tpm->pubkey_uuid[tpm->pubkeynum-1]=dup_str(key_uuid,DIGEST_SIZE*2);
	}
	return 0;
}

int create_vtpm_struct(struct vTPM_info * vtpm,struct vm_info * vm, char * ownerpass,char * srkpass,
		char * signkey_uuid,char * pubkey_uuid)
{
	memset(vtpm,0,sizeof(struct vTPM_info));
	memcpy(vtpm->uuid,vm->uuid,DIGEST_SIZE*2);
	vtpm->ownername=dup_str(vm->owner,0);
	vtpm->tpm_type=VIRTUAL_TPM;
	vtpm->ownerpass=dup_str(ownerpass,0);
	vtpm->srkpass=dup_str(srkpass,0);
	vtpm->wrappedkeynum=1;
	vtpm->pubkeynum=1;
	
	vtpm->wrapkey_uuid=kmalloc(sizeof(char *)*vtpm->wrappedkeynum,GFP_KERNEL);
	vtpm->wrapkey_uuid[0]=dup_str(signkey_uuid,DIGEST_SIZE*2);
	vtpm->pubkey_uuid=malloc(sizeof(char *)*vtpm->pubkeynum);
	vtpm->pubkey_uuid[0]=dup_str(pubkey_uuid,DIGEST_SIZE*2);

	return 0;
}





struct trust_policy_ops vtpm_lib_ops=
{
	"VTPM",
	.initlib=general_initlib,
	.find=general_find,
	.typefind=NULL,
	.gettag=entity_get_uuid,
       	.insert=general_insert,
	.modify=general_modify,
	.remove=general_remove,
	.getfirst=general_getfirst,
	.getnext=general_getnext,
	.comp = NULL,
	.comptag=entity_comp_uuid,
	.typecomptag=NULL,
	.hashfunc=NULL,
	.destroyelem=general_destroyelem,	
	.destroylib=general_destroylib,
};
/*
struct trust_policy_ops wrappedkey_lib_ops=
{
	"BLBK",
	.initlib=general_initlib,
	.find=general_find,
	.typefind=NULL,
	.gettag=entity_get_uuid,
       	.insert=general_insert,
	.modify=general_modify,
	.remove=general_remove,
	.getfirst=general_getfirst,
	.getnext=general_getnext,
	.comp = NULL,
	.comptag=entity_comp_uuid,
	.typecomptag=NULL,
	.hashfunc=NULL,
	.destroyelem=general_destroyelem,	
	.destroylib=general_destroylib,
};

struct trust_policy_ops publickey_lib_ops=
{
	"PUBK",
	.initlib=general_initlib,
	.find=general_find,
	.typefind=NULL,
	.gettag=entity_get_uuid,
       	.insert=general_insert,
	.modify=general_modify,
	.remove=general_remove,
	.getfirst=general_getfirst,
	.getnext=general_getnext,
	.comp = NULL,
	.comptag=entity_comp_uuid,
	.typecomptag=NULL,
	.hashfunc=NULL,
	.destroyelem=general_destroyelem,	
	.destroylib=general_destroylib,
};*/
