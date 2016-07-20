
#include "../include/data_type.h"
#include "../include/struct_deal.h"
#include "../include/vm_policy_desc.h"
#define DIGEST_SIZE 32

static struct struct_elem_attr trust_file_info_desc[] =  //TF_I
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"name",OS210_TYPE_ESTRING,256,NULL},
	{"digest",OS210_TYPE_BINDATA,DIGEST_SIZE,NULL},
	{"info",OS210_TYPE_ESTRING,256,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
static struct struct_elem_attr trust_file_list_desc[] =  //TFLI
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"pcr_index",OS210_TYPE_INT,4,NULL},
	{"file_num",OS210_TYPE_INT,4,NULL},
	{"uuid_list",OS210_TYPE_DEFSTRARRAY,DIGEST_SIZE*2,"file_num"},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
static struct struct_elem_attr trust_digest_list_desc[] =
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"digest_num",OS210_TYPE_INT,4,NULL},
	{"trust_level",OS210_TYPE_INT,4,NULL},
	{"digest_list",OS210_TYPE_DEFSTRARRAY,DIGEST_SIZE,"digest_num"},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
static struct struct_elem_attr trust_file_array_desc[] =
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"list_num",OS210_TYPE_INT,4,NULL},
	{"uuid_list",OS210_TYPE_DEFSTRARRAY,DIGEST_SIZE*2,"list_num"},
	{"info",OS210_TYPE_ESTRING,256,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
//######################################################
static struct struct_elem_attr trust_file_pcr_policy_desc[] =
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"file_list_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"pcr_select",OS210_TYPE_ORGCHAIN,0,tcm_pcr_set_desc},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
//######################################################
static struct struct_elem_attr trust_policy_template_desc[] =
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"producer",OS210_TYPE_ESTRING,256,NULL},
	{"verifier",OS210_TYPE_ESTRING,256,NULL},
	{"policy_num",OS210_TYPE_INT,4,NULL},
	{"policy_pcr_uuid",OS210_TYPE_DEFSTRARRAY,DIGEST_SIZE*2,"policy_num"},
	{"info",OS210_TYPE_ESTRING,256,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
static struct struct_elem_attr trust_policy_define_desc[] =
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"trust_level",OS210_TYPE_INT,4,NULL},
	{"trust_layer",OS210_TYPE_INT,4,NULL},
	{"trust_area",OS210_TYPE_ESTRING,256,NULL},
	{"producer",OS210_TYPE_ESTRING,256,NULL},
	{"verifier",OS210_TYPE_ESTRING,256,NULL},
	{"owner",OS210_TYPE_ESTRING,256,NULL},
	{"policy_num",OS210_TYPE_INT,4,NULL},
	{"policy_set_uuid",OS210_TYPE_DEFSTRARRAY,DIGEST_SIZE*2,"policy_num"},
	{"info",OS210_TYPE_ESTRING,256,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr trust_arch_site_desc[] =
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"trust_level",OS210_TYPE_INT,4,NULL},
	{"trust_layer",OS210_TYPE_INT,4,NULL},
	{"trust_area",OS210_TYPE_ESTRING,256,NULL},
	{"info",OS210_TYPE_ESTRING,256,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
static struct struct_elem_attr trust_arch_frame_desc[] =
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"policy_site_num",OS210_TYPE_INT,4,NULL},
	{"policy_site_uuid",OS210_TYPE_DEFSTRARRAY,DIGEST_SIZE*2,"policy_site_num"},
	{"info",OS210_TYPE_ESTRING,256,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
static struct struct_elem_attr trust_arch_policy_desc[] =
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"trust_arch_frame_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"define_policy_num",OS210_TYPE_INT,4,NULL},
	{"define_policy_uuid",OS210_TYPE_DEFSTRARRAY,DIGEST_SIZE*2,"define_policy_num"},
	{"info",OS210_TYPE_ESTRING,256,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
