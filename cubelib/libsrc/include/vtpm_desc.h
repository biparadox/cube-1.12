#ifndef VTPM_DESC
#define VTPM_DESC
#include "../include/data_type.h"
#include "../include/struct_deal.h"
#define DIGEST_SIZE 32
//the decription struct of vtpm_info

static struct struct_elem_attr vtpm_info_desc[]=
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"platform_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"owner",OS210_TYPE_ESTRING,80,NULL},
	{"tpm_type",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{"port",OS210_TYPE_INT,sizeof(UINT32),NULL},
	{"path",OS210_TYPE_ESTRING,0,NULL},
	{"ownerpass",OS210_TYPE_ESTRING,0,NULL},
	{"srkpass",OS210_TYPE_ESTRING,0,NULL},
	{"pubEK_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"wrappedkeynum",OS210_TYPE_INT,sizeof(int),NULL},
	{"wrapkey_uuid",OS210_TYPE_DEFSTRARRAY,DIGEST_SIZE*2,"wrappedkeynum"},
	{"pubkeynum",OS210_TYPE_INT,sizeof(int),NULL},
	{"pubkey_uuid",OS210_TYPE_DEFSTRARRAY,DIGEST_SIZE*2,"pubkeynum"},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
//the descriptiong struct of keyfile
static struct struct_elem_attr keyfile_data_desc[]=
{
        {"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"filename",OS210_TYPE_ESTRING,1024,NULL},
        {"data_size",OS210_TYPE_INT,sizeof(int),NULL},
        {"key_data",OS210_TYPE_ESTRING,0,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

//extern struct trust_policy_ops vtpm_lib_ops; 
//extern struct trust_policy_ops wrappedkey_lib_ops; 
//extern struct trust_policy_ops publickey_lib_ops;
#endif
