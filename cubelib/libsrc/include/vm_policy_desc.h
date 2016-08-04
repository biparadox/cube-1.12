#ifndef VM_POLICY_DESC_H
#define VM_POLICY_DESC_H
#include "../include/data_type.h"
#include "../include/struct_deal.h"
#define DIGEST_SIZE 32
//the decription struct of vm's policy
static struct struct_elem_attr vm_policy_desc[]=
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"trust_level",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{"owner",OS210_TYPE_ESTRING,0,NULL},
	{"auth_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"policy_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"platform_pcr_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"boot_pcr_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"runtime_pcr_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"policy_describe",OS210_TYPE_ESTRING,0,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

//the descriptiong struct of pcr selection
static struct struct_elem_attr tcm_pcr_selection_desc[]=
{
	{"size_of_select",OS210_TYPE_USHORT,sizeof(short),NULL},
	{"pcr_select",OS210_TYPE_DEFINE,sizeof(unsigned char),"size_of_select"},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

//the description struct of pcr set
static struct struct_elem_attr tcm_pcr_set_desc[]=
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"trust_level",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{"pcr_select",OS210_TYPE_ORGCHAIN,0,&tcm_pcr_selection_desc},
	{"value_size",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{"pcr_value",OS210_TYPE_DEFINE,sizeof(BYTE),"value_size"},
	{"policy_describe",OS210_TYPE_ESTRING,0,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};


//the description struct of policy
static struct struct_elem_attr policy_file_desc[]=
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"policy_type",OS210_TYPE_STRING,4,NULL},
	{"creater",OS210_TYPE_ESTRING,0,NULL},
	{"creater_auth_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"policy_path",OS210_TYPE_ESTRING,0,NULL},
	{"file_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"policy_describe",OS210_TYPE_ESTRING,0,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

//the descriptiong struct of policy file data
static struct struct_elem_attr policyfile_data_desc[]=
{
        {"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"filename",OS210_TYPE_ESTRING,1024,NULL},
        {"total_size",OS210_TYPE_INT,sizeof(int),NULL},
        {"record_no",OS210_TYPE_INT,sizeof(int),NULL},
        {"offset",OS210_TYPE_INT,sizeof(int),NULL},
        {"data_size",OS210_TYPE_INT,sizeof(int),NULL},
        {"policy_data",OS210_TYPE_DEFINE,sizeof(BYTE),"data_size"},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr policyfile_req_desc[]=
{
        {"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"filename",OS210_TYPE_ESTRING,1024,NULL},
        {"requestor",OS210_TYPE_ESTRING,DIGEST_SIZE*2,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr policyfile_store_desc[]=
{
        {"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"filename",OS210_TYPE_ESTRING,1024,NULL},
        {"file_size",OS210_TYPE_INT,sizeof(int),NULL},
        {"block_size",OS210_TYPE_INT,sizeof(int),NULL},
        {"block_num",OS210_TYPE_INT,sizeof(int),NULL},
        {"mark_len",OS210_TYPE_INT,sizeof(int),NULL},
        {"marks",OS210_TYPE_DEFINE,sizeof(BYTE),"mark_len"},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static NAME2VALUE file_trans_state_valuelist[] = 
{
    {"SUCCESS",1},
    {"ERROR",2},
	{NULL,0}
};
static struct struct_elem_attr policyfile_notice_desc[]=
{
        {"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"filename",OS210_TYPE_ESTRING,1024,NULL},
        {"file_type",OS210_TYPE_ENUM,sizeof(int),&file_trans_state_valuelist},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
static struct struct_elem_attr verify_info_desc[]=
{
        {"verify_data_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"entity_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"policy_type",OS210_TYPE_STRING,4,NULL},
        {"trust_level",OS210_TYPE_INT,sizeof(int),NULL},
        {"info_len",OS210_TYPE_INT,sizeof(int),NULL},
        {"info",OS210_TYPE_ESTRING,0,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

#endif
