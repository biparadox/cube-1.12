/*************************************************
*       Hige security Linux Operating System Project
*
*	File description: 	Linux core database function model header file 
*	File name:		logic_baselib.h
*	date:    	2008-05-09
*	Author:    	Hu jun
*************************************************/

#ifndef _OS210_LOGIC_BASELIB_H
#define _OS210_LOGIC_BASELIB_H

//#include "../include/data_type.h"

#define MAX_RECORD_NUM 65536
#define DIGEST_SIZE 32
typedef struct tagPolicyHead{
   	 BYTE NodeSequence[20];      
   	 BYTE UserName[40];            
   	 BYTE PolicyType[4];              
   	 BYTE PolicyVersion[8];        
   	 UINT32  RecordNum;	       
   	 UINT32 Reserved;   		
}__attribute__((packed)) POLICY_HEAD;
typedef struct trust_policy_ops
{
	char name[5];
	void * (*initlib)(void * lib);
//	void * (*gethandle)(char * policytype);
	void * (*find)(void * lib,void * tag);
	void * (*typefind)(int findtype,void * lib,void * tag);
	void * (*gettag)(void * lib,void * policy);
	void * (*insert)(void * lib,void * policy);
	void * (*modify)(void * lib,void * policy,char * name,void * newvalue);
	void * (*remove)(void * lib,void * tag);
	void * (*getfirst)(void * lib);
	void * (*getnext)(void * lib);
	int (*comp)(void * policy1,void * policy2);
	int (*comptag)(void * policy,void * policy_tag);
	int (*typecomptag)(int type,void * policy,void * policy_tag);
	int (*hashfunc)(void * policy);
	void (*destroyelem)(void * lib,void * policy);
	void (*destroylib)(void * lib);
}TPLIB_OPS;

typedef struct tagpolicy_lib
{
	char policy_type[5];
	void * struct_template;
	struct trust_policy_ops * policy_ops;
	void * handle;
	void * curr_record;
}POLICY_LIB;

int logic_baselib_init(void);
void * find_policy_lib(char * policy_type);
void * logic_get_policy_struct_template(char * policy_type);
int register_policy_lib(char * policy_type,struct trust_policy_ops * policy_ops);
/*
extern struct trust_policy_ops sublabel_policy_ops; 
extern struct trust_policy_ops objlabel_policy_ops; 
extern struct trust_policy_ops authuser_policy_ops; 
extern struct trust_policy_ops dac_policy_ops; 
extern struct trust_policy_ops audit_policy_ops; 
*/

void * find_record_type(char * record_type);
int register_record_type(char * type,struct struct_elem_attr * desc);
void * load_record_desc(char  * type);
void * load_record_template(char  * type);
void * load_record_ops(char  * type);

void * general_initlib(void * lib);
void * general_find(void * lib, void * tag);
void * general_typefind(int findtype,void * lib, void * tag);
void * general_insert(void * lib,void * policy);
int general_modify(void * lib,void * policy,char * name,void * newvalue);
void * general_remove(void * lib,void * tag);
void * general_getfirst(void * lib);
void * general_getnext(void * lib);
void * general_destroyelem(void * lib,void * policy);
void * general_destroylib(void * lib);
void * entity_get_uuid(void * lib,void * policy);
int  entity_comp_uuid(void * head, void * uuid);
int entity_hash_uuid(char * type, void * policy);
extern struct trust_policy_ops general_lib_ops;
struct trust_policy_ops *  get_entity_lib_ops(char * policy_type);
#endif

