/*************************************************
*       
*
*	程序名称: 	210系统标记管理程序
*	文件名:		label_manage.c
*	日期:    	2012-01-05
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
#include  "../include/kernel_comp.h"
#include "../include/list.h"

#endif

#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/extern_struct.h"
#include "../include/extern_interface.h"
#include "../include/extern_struct_desc.h"
#include "../include/extern_defno.h"
#include "../include/attrlist.h"
#include "../include/policy_ui.h"
#include "logic_compare.h"
#include "typefind_defno.h"

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


struct os210_core_policy_lib {
	UINT32 ver_no;  //kernel's version no, now is v0.91
	Node_Info nodeinfo; //this machine's No and cert
	unsigned int core_state;  	// core's security state
//	spinlock_t core_lock;     	// 安全状态数据结构自旋锁;
	Record_List policy_lib_list;    // A list with Policy libs

};

typedef struct os210_record_type_elem {
	char type[4];
	struct struct_elem_attr * record_desc;
	struct trust_policy_ops * record_lib_ops;	
}RECORD_DESC;

struct os210_record_type_list {
	UINT32 ver_no;  //kernel's version no, now is v0.91
	Node_Info nodeinfo; //this machine's No and cert
	unsigned int core_state;  	// core's security state
//	spinlock_t core_lock;     	// 安全状态数据结构自旋锁;
	Record_List record_type_list;    // A list with Policy libs
};



static struct os210_core_policy_lib * os210_sec_policy_lib;
static struct os210_record_type_list * os210_record_type_list;
//static void * name_space;

int logic_baselib_init()
{
	os210_record_type_list = kmalloc(sizeof(struct os210_record_type_list),GFP_KERNEL);
	if(os210_record_type_list == NULL)
		return -ENOMEM;
	memset(os210_record_type_list,0,sizeof(struct os210_record_type_list));
	os210_record_type_list->ver_no=0x00000091;
	os210_record_type_list->core_state=0;
	INIT_LIST_HEAD(&(os210_record_type_list->record_type_list.list));	

	os210_sec_policy_lib= kmalloc(sizeof(struct os210_core_policy_lib),GFP_KERNEL);
	if(os210_sec_policy_lib == NULL)
		return -ENOMEM;
	memset(os210_sec_policy_lib,0,sizeof(struct os210_core_policy_lib));
	os210_sec_policy_lib->ver_no=0x00000091;
	os210_sec_policy_lib->core_state=0;
	INIT_LIST_HEAD(&(os210_sec_policy_lib->policy_lib_list.list));	
	return 0;
}

int logic_record_find_type(struct list_head * head,void * tag)
{
	RECORD_DESC * record_type;
 	Record_List * record;

	// 首先对比尾部名称	
	record = list_entry(head,Record_List,list);

	record_type = (RECORD_DESC *) record->record;
	if(record_type==NULL)
        	return -EINVAL;
	return strncmp(record_type->type,(char *) tag,4);
}

void * find_record_type(char * record_type)
{
	struct list_head * libhead, *currlib;
	Record_List * record_elem;

	libhead = &(os210_record_type_list->record_type_list.list);
	currlib=find_elem_with_tag(libhead,logic_record_find_type,record_type);
	if(currlib==NULL)
		return NULL;
	record_elem= (Record_List *)list_entry(currlib,Record_List,list);
	return record_elem->record;
}


int register_record_type(char * type,struct struct_elem_attr * desc)
{
	struct list_head * libhead, *currlib;
	RECORD_DESC * record_type;
	Record_List * record_elem;
	Record_List * record_list;

	record_type=(RECORD_DESC *)find_record_type(type);
	if(record_type != NULL)
		return -EINVAL;

	record_type = kmalloc(sizeof(RECORD_DESC),GFP_KERNEL);
	if(record_type==NULL)
		return -ENOMEM;
	memcpy(record_type->type,type,4);
	record_type->record_desc=desc;
	if(IS_ERR(record_type->record_desc))
		return -EINVAL;
	record_type->record_lib_ops=NULL;

	record_elem = kmalloc(sizeof(Record_List),GFP_KERNEL);
	if(record_elem==NULL)
		return -ENOMEM;
	record_elem->record=record_type;
	INIT_LIST_HEAD(&(record_elem->list));
	libhead = &(os210_record_type_list->record_type_list.list);
	//libhead=&(((Record_List *)handle)->list);
	list_add_tail(&(record_elem->list),libhead);
	return 0;
}

void * load_record_desc(char  * type)
{
	RECORD_DESC * record_type;
	record_type=find_record_type(type);
	if((record_type==NULL) || (IS_ERR(record_type)))
		return record_type;
	return record_type->record_desc;
}

void * load_record_template(char  * type)
{
	void * template;
	struct struct_elem_attr * desc;
	desc=load_record_desc(type);
	if((desc==NULL) || (IS_ERR(desc)))
		return NULL;
	return create_struct_template(desc);
}

void * load_record_ops(char  * type)
{
	RECORD_DESC * record_type;
	record_type=find_record_type(type);
	if((record_type==NULL) || (IS_ERR(record_type)))
		return record_type;
	return record_type->record_lib_ops;
}

int logic_policy_find_lib(struct list_head * head,void * tag)
{
	POLICY_LIB * policylib;
 	Record_List * record;

	// 首先对比尾部名称	
	record = list_entry(head,Record_List,list);

	policylib = (POLICY_LIB *) record->record;
	if(policylib==NULL)
        	return -EINVAL;
	return strncmp(policylib->policy_type,(char *) tag,4);
}

void * find_policy_lib(char * policy_type)
{
	struct list_head * libhead, *currlib;
	Record_List * record_elem;

	libhead = &(os210_sec_policy_lib->policy_lib_list.list);
	currlib=find_elem_with_tag(libhead,logic_policy_find_lib,policy_type);
	if(currlib==NULL)
		return NULL;
	record_elem= (Record_List *)list_entry(currlib,Record_List,list);
	return record_elem->record;
}

void * logic_get_policy_struct(char * policy_type)
{
	POLICY_LIB * currlib;
	currlib=find_policy_lib(policy_type);
	if(currlib==NULL)
		return NULL;
	return currlib->struct_template;
}

int register_policy_lib(char * policy_type,struct trust_policy_ops * policy_ops)
{
	struct list_head * libhead, *currlib;
	POLICY_LIB * policylib;
	Record_List * record_elem;
	Record_List * record_list;
	void * handle;

	policylib=(POLICY_LIB *)find_policy_lib(policy_type);
	if(policylib != NULL)
		return -EINVAL;

	policylib = kmalloc(sizeof(POLICY_LIB),GFP_KERNEL);
		if(policylib==NULL)
			return -ENOMEM;
	memcpy(policylib->policy_type,policy_type,5);
	policylib->struct_template=load_record_template(policy_type);
	if(IS_ERR(policylib->struct_template))
		return policylib->struct_template;
	policylib->policy_ops=policy_ops;
	handle=policylib->policy_ops->initlib(policylib);
	if(handle == NULL)
	       return -EINVAL;
	if(IS_ERR(handle))
		return -EINVAL; 
	policylib->curr_record=NULL;
	policylib->handle=handle;

	record_elem = kmalloc(sizeof(Record_List),GFP_KERNEL);
		if(record_elem==NULL)
			return -ENOMEM;
	record_elem->record=policylib;
	INIT_LIST_HEAD(&(record_elem->list));
	libhead = &(os210_sec_policy_lib->policy_lib_list.list);
	list_add_tail(&(record_elem->list),libhead);
	return 0;
}

void * general_initlib(void * lib) 
// general initlib use a list to store policy
{
	Record_List * record_head;
	POLICY_LIB * policylib;
	policylib=lib;

	if(policylib == NULL)
	       return -EINVAL;
	if(IS_ERR(policylib))
		return -EINVAL; 

	record_head = kmalloc(sizeof(Record_List),GFP_KERNEL);
		if(record_head==NULL)
			return -ENOMEM;
	INIT_LIST_HEAD(&(record_head->list));
	record_head->record=NULL;
	return (void *)record_head;
}

void * general_find(void * lib, void * tag)
// find elem in a list by name
{
	POLICY_LIB * policy_lib;
	Record_List * record_list;
	Record_List * record_elem;
	struct list_head * curr_head;

	policy_lib=(POLICY_LIB *)lib;
	record_list=(Record_List *)(policy_lib->handle);
	curr_head = find_elem_with_tag(record_list,
		policy_lib->policy_ops->comptag,tag);
	if(curr_head == NULL)
		return NULL;
	if(IS_ERR(curr_head))
		return curr_head;
	record_elem=list_entry(curr_head,Record_List,list);
	return record_elem->record;	
}

void * general_typefind(int findtype,void * lib, void * tag)
// find elem in a list by name
{
	POLICY_LIB * policy_lib;
	Record_List * record_list;
	Record_List * record_elem;
	struct list_head * curr_head;

	policy_lib=(POLICY_LIB *)lib;
	record_list=(Record_List *)(policy_lib->handle);
	curr_head = typefind_elem_with_tag(record_list,
		policy_lib->policy_ops->typecomptag,findtype,tag);
	if(curr_head == NULL)
		return NULL;
	if(IS_ERR(curr_head))
		return curr_head;
	record_elem=list_entry(curr_head,Record_List,list);
	return record_elem->record;	
}

void * filename_typefind(int findtype,void * lib, void * tag)
// find elem in a list by name
{
	POLICY_LIB * policy_lib;
	Record_List * record_list;
	Record_List * record_elem;
	Record_List comprecord;
	struct list_head * curr_head;
	OBJ_LABEL * lobjlabel;
	char * name;

	policy_lib=(POLICY_LIB *)lib;
	if(lib==NULL)
		return -EINVAL;
	record_list=(Record_List *)(policy_lib->handle);
	if(record_list==NULL)
		return -EINVAL;
	name=(char *)tag;
	if(name==NULL)
		return -EINVAL; 
	switch(findtype)
	{
		case FINDTYPE_FILENAME_UNINAME:
			curr_head = find_elem_with_tag(record_list,
				label_obj_comp_uniname,
				label_get_tailname(name));	
			break;	
		case FINDTYPE_FILENAME_MATCH:
			/*
	 		lobjlabel = (OBJ_LABEL *)kmalloc(sizeof(OBJ_LABEL),
				GFP_KERNEL);
	  		if(lobjlabel == NULL)
	  			return -ENOMEM;		
			lobjlabel->ObjName.String = name;
			lobjlabel->ObjName.length = strlen(name);
			comprecord.record = lobjlabel;

		// 查找元素的最小上界
			curr_head = find_elem_minupper_inlist(record_list,
				label_obj_match_elem,&(comprecord.list));
			kfree(lobjlabel);
			*/
			curr_head = find_elem_minupper_inlist(record_list,
				label_obj_match_name,name);
			break;
		default:
			return -EINVAL;
	}

	if(curr_head == NULL)
		return NULL;
	if(IS_ERR(curr_head))
		return curr_head;
	record_elem=list_entry(curr_head,Record_List,list);
	return record_elem->record;	
}

void * sublabel_gettag(void * lib,void * policy)
{
	return ((SUB_LABEL *)policy)->SubName.String;

}

void * get_policy_struct(void * lib)
{
	POLICY_LIB * policylib;
	policylib=(POLICY_LIB *)lib;

	return policylib->struct_template;
}


void * general_insert(void * lib,void * policy)
{
	Record_List * recordhead;
	Record_List * newrecord;
	POLICY_LIB * policylib;
	policylib=lib;

	if(policylib == NULL)
	       return -EINVAL;
	if(IS_ERR(policylib))
		return -EINVAL; 

	recordhead = policylib->handle;
	if(recordhead==NULL)
		return -ENOMEM;
	newrecord = kmalloc(sizeof(Record_List),GFP_KERNEL);
	if(newrecord==NULL)
		return -ENOMEM;
	INIT_LIST_HEAD(&(newrecord->list));
	
	newrecord->record=policy;
	list_add_tail(&(newrecord->list),recordhead);
	return newrecord;
}	

int general_modify(void * lib,void * policy,char * name,void * newvalue)
{
	POLICY_LIB * policylib;
	policylib=lib;

	if(policylib == NULL)
	       return -EINVAL;
	if(IS_ERR(policylib))
		return -EINVAL; 
	return struct_read_elem(name,policy,
			newvalue,policylib->struct_template);
}

void * general_remove(void * lib,void * tag)
{
	struct trust_policy_ops * ops;
	struct list_head * curr_head;
	POLICY_LIB * policy_lib=(POLICY_LIB *)lib;
	Record_List * record_list, *record_elem;
	void * record;
	ops=policy_lib->policy_ops;
	if(ops==NULL)
		return -EINVAL;	

	record_list=(Record_List *)(policy_lib->handle);
	curr_head = find_elem_with_tag(record_list,
		ops->comptag,tag);
	if(curr_head == NULL)
		return NULL;

	if(IS_ERR(curr_head))
		return curr_head;

	record_elem=list_entry(curr_head,Record_List,list);
	list_del(curr_head);
	record=record_elem->record;
	kfree(record_elem);	
	return record;
}

void * general_getfirst(void * lib)
{
	Record_List * recordhead;
	Record_List * newrecord;
	POLICY_LIB * policylib;
	policylib=lib;

	if(policylib == NULL)
	       return -EINVAL;
	if(IS_ERR(policylib))
		return -EINVAL; 

	recordhead = policylib->handle;
	if(recordhead==NULL)
		return -ENOMEM;
	policylib->curr_record = (Record_List *)(recordhead->list.next);
	newrecord = list_entry(policylib->curr_record,Record_List,list);
	return newrecord->record;
}

void * general_getnext(void * lib)
{
	Record_List * recordhead;
	Record_List * currrecord;
	Record_List * newrecord;
	POLICY_LIB * policylib;
	policylib=lib;

	if(policylib == NULL)
	       return -EINVAL;
	if(IS_ERR(policylib))
		return -EINVAL; 

	recordhead = policylib->handle;
	if(recordhead==NULL)
		return -ENOMEM;
	if(policylib->curr_record==policylib->handle)
		return NULL;
	currrecord=(Record_List *)policylib->curr_record;
	policylib->curr_record = (Record_List *)(currrecord->list.next);
	newrecord = list_entry(policylib->curr_record,Record_List,list);
	return newrecord->record;
}

void * general_destroyelem(void * lib,void * policy)
{

	POLICY_LIB * policylib;
	policylib=lib;

	if(policylib == NULL)
	       return -EINVAL;
	free_struct(policy,policylib->struct_template);
	return NULL;
}

void * general_destroylib(void * lib)
{
	return NULL;
}

int LoadPolicyData(BYTE * buffer)
{
	POLICY_LIB * lib;
	struct struct_elem_attr * desc;
	struct trust_policy_ops * ops;
	POLICY_HEAD * head;
	int recordnum;
        int retval;	
	void * label;
	void * tag;
	void * struct_template;

	if((buffer == NULL) || (IS_ERR(buffer)))
		return buffer;

	head=(POLICY_HEAD *)buffer;
	
	lib=(POLICY_LIB *)find_policy_lib(head->PolicyType);
	if((lib == NULL) || (IS_ERR(lib)))
		return lib;
	recordnum=head->RecordNum;

	struct_template=lib->struct_template;
	ops=lib->policy_ops;

	int i;
	void * templabel;
	int offset=sizeof(POLICY_HEAD);
	for(i=0;i<recordnum;i++)
	{
		retval=alloc_struct(&label,struct_template);
		if((label==NULL)||(IS_ERR(label)))
			return label;
		retval=blob_2_struct(buffer+offset,label,struct_template);
		if(retval<=0)
			return retval;
		offset+=retval;
		tag=ops->gettag(lib,label);
		templabel=ops->find(lib,tag);
		if(templabel!=NULL)
		{
			ops->remove(lib,tag);	
		}
		templabel=ops->insert(lib,label);
		
	}
	return offset;
}
	

struct trust_policy_ops sublabel_policy_ops=
{
	"SUBL",
	.initlib=general_initlib,
	.find=general_find,
	.typefind=NULL,
	.gettag=sublabel_gettag,
       	.insert=general_insert,
	.modify=general_modify,
	.remove=general_remove,
	.getfirst=general_getfirst,
	.getnext=general_getnext,
	.comp = NULL,
	.comptag=label_sub_comp_name,
	.typecomptag=NULL,
	.hashfunc=NULL,
	.destroyelem=general_destroyelem,	
	.destroylib=general_destroylib,
};

struct trust_policy_ops objlabel_policy_ops=
{
	"OBJL",
	.initlib=general_initlib,
	.find=general_find,
	.typefind=filename_typefind,
	.gettag=sublabel_gettag,
       	.insert=general_insert,
	.modify=general_modify,
	.remove=general_remove,
	.getfirst=general_getfirst,
	.getnext=general_getnext,
	.comp = NULL,
	.comptag=label_obj_comp_name,
	.typecomptag=NULL,
	.hashfunc=NULL,
	.destroyelem=general_destroyelem,	
	.destroylib=general_destroylib,
};

struct trust_policy_ops dac_policy_ops=
{
	"DACF",
	.initlib=general_initlib,
	.find=general_find,
	.typefind=NULL,
	.gettag=sublabel_gettag,
       	.insert=general_insert,
	.modify=general_modify,
	.remove=general_remove,
	.getfirst=general_getfirst,
	.getnext=general_getnext,
	.comp = NULL,
	.comptag=label_dac_comp_record,
	.hashfunc=NULL,
	.destroyelem=general_destroyelem,	
	.destroylib=general_destroylib,
};
struct trust_policy_ops authuser_policy_ops=
{
	"AUUL",
	.initlib=general_initlib,
	.find=general_find,
	.typefind=general_typefind,
	.gettag=sublabel_gettag,
       	.insert=general_insert,
	.modify=general_modify,
	.remove=general_remove,
	.getfirst=general_getfirst,
	.getnext=general_getnext,
	.comp = NULL,
	.comptag=label_userid_comp_userid,
	.typecomptag=label_authuser_typecomp,
	.hashfunc=NULL,
	.destroyelem=general_destroyelem,	
	.destroylib=general_destroylib,
};

int GetFirstPolicy(void ** record,char * policytype)
{
	POLICY_LIB * lib;
	void * test;
	lib=find_policy_lib(policytype);
	if(lib==NULL)
		return -EINVAL;
	*record = lib->policy_ops->getfirst(lib);
	return 0;
}

int GetNextPolicy(void ** record,char * policytype)
{
	POLICY_LIB * lib;
	lib=find_policy_lib(policytype);
	if(lib==NULL)
		return -EINVAL;
	*record = lib->policy_ops->getnext(lib);
	return 0;
}

int AddPolicy(void * policy,char * policytype)
{
	POLICY_LIB * lib;
	void * tag;
	void * templabel;
	struct trust_policy_ops * ops;

	lib=find_policy_lib(policytype);
	if(lib==NULL)
		return -EINVAL;
	ops=lib->policy_ops;
	tag=ops->gettag(lib,policy);
	templabel=ops->find(lib,tag);
	if(templabel!=NULL)
	{
		templabel=ops->remove(lib,tag);
		ops->destroyelem(lib,templabel);	
	}
	templabel=ops->insert(lib,policy);
		
//	return templabel;
	return 1;
}
int ModPolicy(void * policy,char * name,char * newvalue,char * policytype)
{
	POLICY_LIB * lib;
	void * tag;
	struct trust_policy_ops * ops;
	int retval;

	lib=find_policy_lib(policytype);
	if(lib==NULL)
		return -EINVAL;
	ops=lib->policy_ops;
	retval=ops->modify(lib,policy,name,newvalue);
	return retval;
}

int DelPolicy(void * tag,char * policytype)
{
	POLICY_LIB * lib;
	struct trust_policy_ops * ops;
	int retval;

	lib=find_policy_lib(policytype);
	if(lib==NULL)
		return -EINVAL;
	ops=lib->policy_ops;
	retval=ops->remove(lib,tag);
	return retval;
}

//void * FindPolicy(void * tag,char * policytype)
int FindPolicy(void * tag,char * policytype,void ** policy)
{
	POLICY_LIB * lib;
	void * templabel;
	struct trust_policy_ops * ops;
	*policy=NULL;

	lib=find_policy_lib(policytype);
	if(lib==NULL)
		return NULL;
	ops=lib->policy_ops;
	templabel=ops->find(lib,tag);
//	return templabel;
	*policy=templabel;
	return 1;
}

void * TypeFindPolicy(int findtype,void * tag,char * policytype)
{
	POLICY_LIB * lib;
	void * templabel;
	struct trust_policy_ops * ops;

	lib=find_policy_lib(policytype);
	if(lib==NULL)
		return NULL;
	ops=lib->policy_ops;
	templabel=ops->typefind(findtype,lib,tag);
	return templabel;
}

void * DupPolicy(void * policy,char * policytype)
{
	void * struct_template=load_record_template(policytype);
	if(struct_template==NULL)
		return NULL;
	return clone_struct(policy,struct_template);

}

struct entity_struct_head
{
	BYTE uuid[DIGEST_SIZE*2];
	BYTE data[0];
};

void * entity_get_uuid(void * lib,void * policy)
{
	return ((struct entity_struct_head *)policy)->uuid;

}
int entity_hash_uuid(char * type, void * policy)
{
	void * struct_template;
	int curr_offset;
	BYTE buffer[2048];
	BYTE digest[DIGEST_SIZE];
	int ret;
	struct_template=load_record_template(type);
	if(struct_template==NULL)
		return -EINVAL;
		
	ret=struct_2_blob(policy,buffer,struct_template);
	if(ret<0)
		return ret;
	if(ret<DIGEST_SIZE*2)
		return -EINVAL;

	ret=calculate_context_sm3(buffer+DIGEST_SIZE*2,ret-DIGEST_SIZE*2,digest);
	if(ret<0)
		return -EINVAL;
	digest_to_uuid(digest,policy);
	memset(buffer,0,ret);
	
	return 0;
}


int entity_comp_uuid(void * list_head, void * name) 
{                                                             
	struct list_head * head;
	struct entity_struct_head * entity_head;    
	head=(struct list_head *)list_head;
	if(head==NULL)
		return -EINVAL;	
	Record_List * record;                             
	char * string;
	string=(char *)name;
	record = list_entry(head,Record_List,list);              
	entity_head = (struct entity_struct_head *) record->record;                      
	if(entity_head == NULL)
		return -EINVAL;
	if(entity_head->uuid==NULL)
		return -EINVAL;
	return strncmp(entity_head->uuid,string,DIGEST_SIZE*2);        
}

struct trust_policy_ops general_lib_ops=
{
	"NULL",
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

struct trust_policy_ops * get_entity_lib_ops(char * policy_type)
{
	struct trust_policy_ops * lib_ops;
	lib_ops=(struct trust_policy_ops *)kmalloc(sizeof(struct trust_policy_ops),GFP_KERNEL);
	if(lib_ops==NULL)
		return -ENOMEM;
	memcpy(lib_ops,&general_lib_ops,sizeof(struct trust_policy_ops));
	memset(lib_ops->name,0,5);
	memcpy(lib_ops->name,policy_type,4);
	return lib_ops;
}
