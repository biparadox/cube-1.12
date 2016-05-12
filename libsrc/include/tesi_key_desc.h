#ifndef KEY_CERTIFY_DESC_H
#define KEY_CERTIFY_DESC_H


static NAME2VALUE key_usage_list[] = 
{
	{"TPM_KEY_SIGNING",0x0010},
	{"TPM_KEY_STORAGE",0x0011},
	{"TPM_KEY_IDENTITY",0x0012},
	{"TPM_KEY_AUTHCHANGE",0x0013},
	{"TPM_KEY_BIND",0x0014},
	{"TPM_KEY_LEGACY",0x0015},
	{"TPM_KEY_MIGRATE",0x0016},
	{NULL,0}
};

static NAME2VALUE key_flags_list[] = 
{
	{"TPM_REDIRECTION",0x00000001},
	{"TPM_MIGRATABLE",0x00000002},
	{"TPM_VOLATILE",0x00000004},
	{"TPM_PCRIGNOREDONREAD",0x00000008},
	{"TPM_MIGRATEAUTHORITY",0x00000010},
	{NULL,0}
};

static NAME2VALUE tpm_auth_data_usage[] = 
{
	{"TPM_AUTH_NEVER",0x00},
	{"TPM_AUTH_ALWAYS",0x01},
	{"TPM_AUTH_PRIV_USE_ONLY",0x11},
	{NULL,0}
};

//the descriptiong struct of wrappedkey   // BLBK
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
	{"keydigestsize",OS210_TYPE_INT,sizeof(int),NULL},
	{"pubkeydigest",OS210_TYPE_DEFSTR,0,"keydigestsize"},
	{"keypass",OS210_TYPE_ESTRING,0,NULL},
	{"key_filename",OS210_TYPE_ESTRING,0,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
//the descriptiong struct of publickey  // PUBK
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
	{"keydigestsize",OS210_TYPE_INT,sizeof(int),NULL},
	{"pubkeydigest",OS210_TYPE_DEFSTR,0,"keydigestsize"},
        {"keypass",OS210_TYPE_ESTRING,0,NULL},
        {"key_filename",OS210_TYPE_ESTRING,0,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr key_cert_desc[]=  // TKCI
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"keyuuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"aikuuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"keyusage",TPM_TYPE_UINT16,sizeof(UINT16),NULL},
	{"keyflags",OS210_TYPE_FLAG,sizeof(UINT32),NULL},
	{"authdatausage",OS210_TYPE_UCHAR,sizeof(BYTE),NULL},
	{"keydigestsize",OS210_TYPE_INT,sizeof(int),NULL},
	{"pubkeydigest",OS210_TYPE_DEFSTR,0,"keydigestsize"},
	{"PCRinfosize",OS210_TYPE_INT,sizeof(int),NULL},
	{"PCRinfos",OS210_TYPE_DEFSTR,0,"PCRinfosize"},
	{"filename",OS210_TYPE_ESTRING,DIGEST_SIZE*2+10,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

#endif
