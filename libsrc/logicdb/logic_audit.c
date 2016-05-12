/*************************************************
*       
*
*	程序名称: 	210系统标记管理程序
*	文件名:		label_manage.c
*	日期:    	2008-05-19
*	作者:    	胡俊
*	模块描述:  	210系统标记的管理、查询
* 修改记录:       
* 修改描述:       
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

#endif

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/extern_struct.h"
#include "../include/extern_interface.h"
#include "../include/extern_struct_desc.h"
#include "../include/extern_defno.h"
#include "../include/attrlist.h"
#include "logic_compare.h"

#include "../include/logic_baselib.h"

typedef struct tagNodeInfo
{
	  BYTE NodeSequence[32];
	  void * Cert;
}Node_Info;

typedef struct tagKeyInfo
{
	 	BYTE KeyID[16];
	 	BYTE * AuthData; 
}Key_Info;

void * audit_initlib(void * lib) 
// general initlib use a list to store policy
{
	Record_List * record_head;
	char * buf;
	POLICY_LIB * policy_lib;
	policy_lib=lib;

	if(policy_lib == NULL)
	       return -EINVAL;
	if(IS_ERR(policy_lib))
		return -EINVAL; 

	buf = kmalloc(sizeof(AUDIT_POLICY)*(AUDIT_PROBE_END+5),
		GFP_KERNEL);
	if(buf==NULL)
		return -ENOMEM;
	policy_lib->handle=buf;
	policy_lib->curr_record=buf;
	AUDIT_POLICY * policy=(AUDIT_POLICY *)buf;
	int i;
	for(i=0;i<AUDIT_PROBE_END-1;i++)
	{
		policy->NodeID=i+1;
		policy=(AUDIT_POLICY *)(buf+sizeof(AUDIT_POLICY));
	}
	return (void *)buf;
}

void * auditpolicy_find(void * lib, void * tag)
// find elem in a list by name
{
	POLICY_LIB * policy_lib;
	policy_lib=(POLICY_LIB *)lib;
	int ProbeNo = (int)tag;
	if((ProbeNo<1)|| (ProbeNo>AUDIT_PROBE_END-1))
		return -EINVAL;	
	return policy_lib->handle + sizeof(AUDIT_POLICY)*(ProbeNo-1);	
}

void * audit_gettag(void * lib,void * policy)
{
	POLICY_LIB * policy_lib;
	policy_lib=(POLICY_LIB *)lib;

	if(policy<(policy_lib->handle))
		return -EINVAL;
	int offset=policy-(void *)policy_lib;
	if((offset%sizeof(AUDIT_POLICY))!=0)
		return -EINVAL;
	if((offset/sizeof(AUDIT_POLICY))>AUDIT_PROBE_END-1)
		return -EINVAL;
	return offset+1;
}

void * audit_insert(void * lib,void * policy)
{
	POLICY_LIB * policylib;
	policylib=lib;
	AUDIT_POLICY * auditpolicy=policy;

	if(policylib == NULL)
	       return -EINVAL;
	if(IS_ERR(policylib))
		return -EINVAL;
	if((auditpolicy->NodeID<1) &&
		(auditpolicy->NodeID>(AUDIT_PROBE_END-1)))
		return -EINVAL;
        int offset=(auditpolicy->NodeID-1)*sizeof(AUDIT_POLICY);
	memcpy(policylib->handle+offset,policy,sizeof(AUDIT_POLICY));
	return policylib->handle+offset;
}	

void * audit_remove(void * lib,void * tag)
{
	POLICY_LIB * policy_lib;
	policy_lib=(POLICY_LIB *)lib;
	AUDIT_POLICY * auditpolicy;
	int ProbeNo = (int)tag;
	if((ProbeNo<1)|| (ProbeNo>AUDIT_PROBE_END-1))
		return -EINVAL;	
	auditpolicy=policy_lib->handle+sizeof(AUDIT_POLICY)*(ProbeNo-1);
	memset(auditpolicy,0,sizeof(AUDIT_POLICY));
	auditpolicy->NodeID=ProbeNo;
	return NULL;	
}

void * audit_getfirst(void * lib)
{
	POLICY_LIB * policylib;
	policylib=lib;

	if(policylib == NULL)
	       return -EINVAL;
	if(IS_ERR(policylib))
		return -EINVAL; 

	policylib->curr_record=policylib->handle;
	return policylib->curr_record;
}

void * audit_getnext(void * lib)
{
	POLICY_LIB * policylib;
	policylib=lib;

	if(policylib == NULL)
	       return -EINVAL;
	if(IS_ERR(policylib))
		return -EINVAL; 

	policylib->curr_record += sizeof(AUDIT_POLICY);
	int CurrProbeNo=(policylib->curr_record-policylib->handle)
		/sizeof(AUDIT_POLICY);
	if(CurrProbeNo>=(AUDIT_PROBE_END-1))
		return NULL;
	return policylib->curr_record;
}

void * audit_destroyelem(void * lib,void * policy)
{
	return NULL;
}

void * audit_destroylib(void * lib)
{
	POLICY_LIB * policylib;
	policylib=lib;

	if(policylib == NULL)
	       return -EINVAL;
	if(IS_ERR(policylib))
		return -EINVAL; 
	kfree(policylib->handle);
	kfree(lib);
	return NULL;
}



struct trust_policy_ops audit_policy_ops=
{
	"AUDI",
	.initlib=audit_initlib,
	.find=auditpolicy_find,
	.typefind=NULL,
	.gettag=audit_gettag,
       	.insert=audit_insert,
	.modify=general_modify,
	.remove=audit_remove,
	.getfirst=audit_getfirst,
	.getnext=audit_getnext,
	.comp = NULL,
	.comptag=NULL,
	.typecomptag=NULL,
	.hashfunc=NULL,
	.destroyelem=audit_destroyelem,	
	.destroylib=audit_destroylib,
};
