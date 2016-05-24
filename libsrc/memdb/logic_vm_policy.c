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

#include "../include/logic_baselib.h"
#include "../include/vm_policy.h"
#include "../include/vm_policy_desc.h"

#include "logic_compare.h"
#define DIGEST_SIZE 32
#define PCR_SELECT_NUM 24
#define PCR_SIZE  20

int compute_pcr_set_uuid(void * pcrs)
{
	BYTE * buffer;
	int blobsize;
	BYTE digest[DIGEST_SIZE];
	struct tcm_pcr_set * pcr_set=pcrs;
	void * template=create_struct_template(tcm_pcr_set_desc);
	if((template==NULL) || IS_ERR(template))
		return -EINVAL;
	buffer=kmalloc(4096,GFP_KERNEL);
	if(buffer==NULL)
	{
//		free_struct_template(template);
		return -ENOMEM;
	}
	blobsize=struct_2_blob(pcr_set,buffer,template);
	blobsize=struct_2_part_blob(pcr_set,buffer,template,"pcr_select,value_size,pcr_value");
	if(blobsize<=0)
	{
//		free_struct_template(template);
		free(buffer);
		return -EINVAL;
	}
	memset(pcr_set->uuid,0,DIGEST_SIZE*2);
	calculate_context_sm3(buffer,blobsize,digest);
	digest_to_uuid(digest,pcr_set->uuid);
//	free_struct_template(template);
	free(buffer);
	return 0;
}

int compute_policy_set_uuid(void * pcrs)
{
	BYTE * buffer;
	int blobsize;
	BYTE digest[DIGEST_SIZE];
	struct tcm_pcr_set * pcr_set=pcrs;
	void * template=create_struct_template(policy_file_desc);
	if((template==NULL) || IS_ERR(template))
		return -EINVAL;
	buffer=kmalloc(4096,GFP_KERNEL);
	if(buffer==NULL)
	{
		return -ENOMEM;
	}
	blobsize=struct_2_blob(pcr_set,buffer,template);
	if(blobsize<=0)
	{
		free(buffer);
		return -EINVAL;
	}
	memset(pcr_set->uuid,0,DIGEST_SIZE*2);
	calculate_context_sm3(buffer,blobsize,digest);
	digest_to_uuid(digest,pcr_set->uuid);
	free(buffer);
	return 0;
}


void * build_empty_pcr_set()
{
	struct tcm_pcr_set * pcr_set;

	pcr_set=kmalloc(sizeof(struct tcm_pcr_set),GFP_KERNEL);
	if(pcr_set==NULL)
		return NULL;
	memset(pcr_set,0,sizeof(struct tcm_pcr_set));
	pcr_set->pcr_select.size_of_select=PCR_SELECT_NUM/8;
	pcr_set->pcr_select.pcr_select=kmalloc(pcr_set->pcr_select.size_of_select,GFP_KERNEL);
	if(pcr_set->pcr_select.pcr_select==NULL)
	{
		kfree(pcr_set);
		return NULL;
	}
	memset(pcr_set->pcr_select.pcr_select,0,pcr_set->pcr_select.size_of_select);
	compute_pcr_set_uuid(pcr_set);
	return pcr_set;
}	

int add_pcr_to_set(void * pcrs,int index,BYTE * value)
{
	struct tcm_pcr_set * pcr_set=(struct tcm_pcr_set *)pcrs;
	struct tcm_pcr_selection * pcr_select;
	int pcr_select_offset;
	BYTE select_value;
	BYTE digest[DIGEST_SIZE];
	int i;
	int pcr_value_offset;

	if((index<0) || (index>=PCR_SELECT_NUM))
		return -EINVAL;
		
	pcr_select=&(pcr_set->pcr_select);
	pcr_select_offset=index/8;
	select_value=1<<(index%8);

	if(select_value&pcr_select->pcr_select[pcr_select_offset])
		// this pcr index is already be selected by this pcr set
	{
		pcr_value_offset=0;
		for(i=0;i<index;i++)
		{
			pcr_select_offset=i/8;
			select_value=1<<(i%8);
			if(select_value&pcr_select->pcr_select[pcr_select_offset])
				pcr_value_offset+=PCR_SIZE;
		}		
		// do the pcr extend
		extend_pcr_sm3digest(pcr_set->pcr_value+pcr_value_offset,value);
	}
	else
	{
		pcr_set->value_size+=PCR_SIZE;
		char * buffer=kmalloc(pcr_set->value_size,GFP_KERNEL);
		memset(buffer,0,pcr_set->value_size);
		pcr_value_offset=0;
		for(i=0;i<PCR_SELECT_NUM;i++)
		{
			if(i<index)
			{
				pcr_select_offset=i/8;
				select_value=1<<(i%8);
				if(select_value&pcr_select->pcr_select[pcr_select_offset])
				{
					memcpy(buffer+pcr_value_offset,pcr_set->pcr_value+pcr_value_offset,PCR_SIZE);
					pcr_value_offset+=PCR_SIZE;
				}

			}
			else if(i==index)
			{
				pcr_select_offset=i/8;
				select_value=1<<(i%8);
				pcr_select->pcr_select[pcr_select_offset]|=select_value;
				extend_pcr_sm3digest(buffer+pcr_value_offset,value);
				pcr_value_offset+=PCR_SIZE;
			}
			else 
			{
				pcr_select_offset=i/8;
				select_value=1<<(i%8);
				if(select_value&pcr_select->pcr_select[pcr_select_offset])
				{
					memcpy(buffer+pcr_value_offset,pcr_set->pcr_value+pcr_value_offset-PCR_SIZE,PCR_SIZE);
					pcr_value_offset+=PCR_SIZE;
				}

			}
		}
		if(pcr_set->pcr_value!=NULL)
			free(pcr_set->pcr_value);
		pcr_set->pcr_value=buffer;

	}
	compute_pcr_set_uuid(pcr_set);
	return 0;
}

void * get_single_pcr_from_set(void * pcrs,int index)
{
	struct tcm_pcr_set * pcr_set=(struct tcm_pcr_set *)pcrs;
	struct tcm_pcr_selection * pcr_select;
	int pcr_select_offset;
	struct tcm_pcr_set * single_pcr;

	BYTE select_value;
	BYTE digest[DIGEST_SIZE];
	int i;
	int pcr_value_offset;
	char *buffer;


	if((index<0) || (index>=PCR_SELECT_NUM))
		return NULL;
		
	pcr_select=&(pcr_set->pcr_select);
	pcr_select_offset=index/8;
	select_value=1<<(index%8);

	if(!(select_value&pcr_select->pcr_select[pcr_select_offset]))
		// this pcr index is not selected by this pcr set
		return NULL;
	single_pcr=build_empty_pcr_set();
	pcr_value_offset=0;
	for(i=0;i<index;i++)
	{
		pcr_select_offset=i/8;
		select_value=1<<(i%8);
		if(select_value&pcr_select->pcr_select[pcr_select_offset])
			pcr_value_offset+=PCR_SIZE;
	}	
	if(pcr_value_offset+PCR_SIZE>pcr_set->value_size)
		return NULL;

	buffer=kmalloc(PCR_SIZE,GFP_KERNEL);
	if(buffer==NULL)
		return NULL;
	memcpy(buffer,pcr_set->pcr_value+pcr_value_offset,PCR_SIZE);	
	single_pcr->value_size=PCR_SIZE;
	single_pcr->pcr_value=buffer;
	pcr_select_offset=index/8;
	select_value=1<<(index%8);
	single_pcr->pcr_select.pcr_select[pcr_select_offset]=select_value;

	compute_pcr_set_uuid(single_pcr);
	return single_pcr;
}

void * build_policy_file(char * creater,char *policy_type,BYTE * key_uuid,char * filename)
{
	struct policy_file * policy;
	BYTE digest[DIGEST_SIZE];
	BYTE *buffer;


	policy=kmalloc(sizeof(struct policy_file),GFP_KERNEL);
	if(policy==NULL)
		return NULL;
	buffer=kmalloc(128,GFP_KERNEL);
	if(buffer==NULL)
	{
		free(policy);
		return NULL;
	}
	memset(buffer,0,128);
	memset(policy,0,sizeof(struct policy_file));
	if(creater!=NULL)
		policy->creater=dup_str(creater,0);
	if(policy_type!=NULL)
		memcpy(policy->policy_type,policy_type,4);
	if(key_uuid!=NULL)
	{
		strncpy(buffer,creater,40);
		int offset=strlen(buffer)+1;
		if(offset>40)
			offset=40;
		strncpy(buffer+offset,key_uuid,DIGEST_SIZE*2);
		offset+=DIGEST_SIZE*2;
		calculate_context_sm3(buffer,offset,digest);
		digest_to_uuid(digest,policy->creater_auth_uuid);
	}

	policy->policy_path=dup_str(filename,0);
	calculate_sm3(filename,digest);
	digest_to_uuid(digest,policy->file_uuid);
	compute_policy_set_uuid(policy);
	free(buffer);
	return policy;
}	




/*
struct trust_policy_ops vm_policy_lib_ops=
{
	"VMPL",
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

struct trust_policy_ops policy_file_lib_ops=
{
	"DIGL",
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

struct trust_policy_ops pcr_set_lib_ops=
{
	"PCRS",
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
*/
