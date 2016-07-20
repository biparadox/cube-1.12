#include "../include/data_type.h"
#include "../include/struct_deal.h"
#define DIGEST_SIZE 32
//the decription struct of vtpm_info
static struct struct_elem_attr vtpm_info_desc[]=
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
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
//the descriptiong struct of wrappedkey
static struct struct_elem_attr wrappedkey_desc[]=
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"vtpm_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"issrkwrapped",OS210_TYPE_INT,sizeof(int),NULL},
	{"key_type",OS210_TYPE_INT,sizeof(int),NULL},
	{"key_alg",OS210_TYPE_INT,sizeof(int),NULL},
	{"key_size",OS210_TYPE_INT,sizeof(int),NULL},
	{"key_binding_policy_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"wrapkey_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"keypass",OS210_TYPE_ESTRING,0,NULL},
	{"key_filename",OS210_TYPE_ESTRING,0,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
//the descriptiong struct of publickey
static struct struct_elem_attr publickey_desc[]=
{
        {"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"vtpm_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"ispubek",OS210_TYPE_INT,sizeof(int),NULL},
        {"key_type",OS210_TYPE_INT,sizeof(int),NULL},
        {"key_alg",OS210_TYPE_INT,sizeof(int),NULL},
        {"key_size",OS210_TYPE_INT,sizeof(int),NULL},
        {"key_binding_policy_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"privatekey_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
        {"keypass",OS210_TYPE_ESTRING,0,NULL},
        {"key_filename",OS210_TYPE_ESTRING,0,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
extern struct trust_policy_ops vtpm_lib_ops; 
extern struct trust_policy_ops wrappedkey_lib_ops; 
extern struct trust_policy_ops publickey_lib_ops;
