
#include "../include/data_type.h"
#include "../include/struct_deal.h"
#define DIGEST_SIZE 32

static NAME2VALUE trust_format_valuelist[] = 
{
	{"NULL",TF_NULL},
	{"ENTITY",TF_ENTITY},
	{"SUBJECT",TF_SUBJECT},
	{"OBJECT",TF_OBJECT},
	{"MBR",TF_MBR},
	{"FILE",TF_FILE},
	{"LIST",TF_LIST},
	{"CHECK",TF_CHECK},
	{"USER",TF_USER},
	{"ROLE",TF_ROLE},
	{"PROC",TF_PROC},
	{"PORT",TF_PORT},
	{"CHANNEL",TF_CHANNEL},
	{"HOLE",TF_HOLE},
	{"ARRAY",TF_ARRAY},
	{"FRAME",TF_FRAME},
	{"POLICY",TF_POLICY},
	{"AUDIT",TF_AUDIT},
	{"TRUST",TF_TRUST},
	{"SET",TF_SET},
	{NULL,0}
};

static NAME2VALUE trust_set_type_valuelist[] = 
{
	{"FUNCTION",TS_FUNCTION_SET},
	{"MECHANISM",TS_MECHANISM_SET},
	{"POLICY",TS_POLICY_SET},
	{"SUPPORT",TS_SUPPORT_SET},
	{"COMP_AREA",TS_COMP_AREA},
	{"DOM_BOUNDARY",TS_DOM_BOUNDARY},
	{"COMM_CONN",TS_COMM_CONN},
	{"CHOICE_SET",TS_CHOICE_SET},
	{"MIX_SET",TS_MIX_SET},
	{"SEC_SYSTEM",TS_SEC_SYSTEM},
	{NULL,0}
};

static NAME2VALUE trust_policy_type_valuelist[] = 
{
	{"ORIGIN",TP_ORIGIN_POLICY},
	{"VERIFY",TP_VERIFY_POLICY},
	{"DEPLOY",TP_DEPLOYMENT_POLICY},
	{"RUNNING",TP_RUNNING_POLICY},
	{NULL,0}
 
};
static NAME2VALUE trust_flag_valuelist[]=
{
	{"STATIC",TF_TRUST_STATIC},
	{"DYNAMIC",TF_TRUST_DYNAMIC},
	{"AND",TF_TRUST_AND},
	{"OR",TF_TRUST_OR},
	{"NOT",TF_TRUST_NOT},
	{NULL,0}
};

static struct struct_elem_attr tcm_pcr_selection_desc[]=
{
	{"size_of_select",OS210_TYPE_USHORT,sizeof(short),NULL},
	{"pcr_select",OS210_TYPE_DEFINE,sizeof(unsigned char),"size_of_select"},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr tcm_pcr_composite_desc[]=
{
	{"pcr_select",OS210_TYPE_ORGCHAIN,0,&tcm_pcr_selection_desc},
	{"value_size",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{"pcr_value",OS210_TYPE_DEFINE,sizeof(BYTE),"value_size"},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
static struct struct_elem_attr trust_policy_head_desc[] =  //TP_H
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"main_type",OS210_TYPE_ENUM,4,&trust_format_valuelist},
	{"sub_type",OS210_TYPE_ENUM,4,&trust_set_type_valuelist},
	{"set_flag",OS210_TYPE_FLAG,4,&trust_flag_valuelist},
	{"name",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"format_size",OS210_TYPE_INT,sizeof(int),NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
static struct struct_elem_attr trust_mbr_info_desc[] =  //TF_I
{
	{"dev_name",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"digest",OS210_TYPE_BINDATA,DIGEST_SIZE,NULL},
	{"info",OS210_TYPE_ESTRING,512,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr trust_file_info_desc[] =  //TF_I
{
	{"name",OS210_TYPE_ESTRING,256,NULL},
	{"digest",OS210_TYPE_BINDATA,DIGEST_SIZE,NULL},
	{"info",OS210_TYPE_ESTRING,512,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr trust_file_list_desc[] =  //TFLI
{
	{"file_num",OS210_TYPE_INT,sizeof(int),NULL},
	{"uuid_list",OS210_TYPE_DEFSTRARRAY,DIGEST_SIZE*2,"file_num"},
	{"info",OS210_TYPE_ESTRING,512,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr trust_check_info_desc[] =  //TFLI
{
	{"check_data_length",OS210_TYPE_INT,sizeof(int),NULL},
	{"check_data",OS210_TYPE_DEFINE,1,"check_data_length"},
	{"info",OS210_TYPE_ESTRING,512,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr trust_digest_desc[] =  //TFLI
{
	{"digest",OS210_TYPE_BINDATA,DIGEST_SIZE,NULL},
	{"info",OS210_TYPE_ESTRING,512,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr trust_digest_list_desc[] =
{
	{"digest_num",OS210_TYPE_INT,sizeof(int),NULL},
	{"digest_list",OS210_TYPE_DEFSTRARRAY,DIGEST_SIZE,"digest_num"},
	{"info",OS210_TYPE_ESTRING,512,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr trust_attr_desc[] =
{
	{"trust_type",OS210_TYPE_ENUM,sizeof(UINT32),&trust_policy_type_valuelist},
	{"trust_level",TPM_TYPE_UINT32,sizeof(UINT32),NULL},
	{"trust_layer",TPM_TYPE_UINT32,sizeof(UINT32),NULL},
	{"trust_area",OS210_TYPE_ESTRING,DIGEST_SIZE*4,NULL},
	{"producer",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
	{"verifier",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
	{"owner",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
	{"info",OS210_TYPE_ESTRING,512,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr trust_set_list[] =
{
	{"list_num",OS210_TYPE_INT,sizeof(int),NULL},
	{"uuid_list",OS210_TYPE_DEFSTRARRAY,DIGEST_SIZE*2,"list_num"},
	{"info",OS210_TYPE_ESTRING,256,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr trust_pcr_set_desc[] =
{
	{"pcrs",OS210_TYPE_ORGCHAIN,0,&tcm_pcr_composite_desc},
	{"info",OS210_TYPE_ESTRING,256,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
