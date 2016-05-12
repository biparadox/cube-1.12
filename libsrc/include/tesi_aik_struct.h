
#ifndef TESI_AIK_STRUCT_H
#define TESI_AIK_STRUCT_H

struct aik_user_info  // USRI
{
	char uuid[DIGEST_SIZE*2];
	char * org;
	char user_id[DIGEST_SIZE];
	char * user_name;
	char * role;
}__attribute__((packed));


static struct struct_elem_attr aik_user_info_desc[]=
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"org",OS210_TYPE_ESTRING,DIGEST_SIZE*2,NULL},
	{"user_id",OS210_TYPE_STRING,DIGEST_SIZE,NULL},
	{"user_name",OS210_TYPE_ESTRING,DIGEST_SIZE*2,NULL},
	{"role",OS210_TYPE_ESTRING,DIGEST_SIZE*2,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

struct aik_cert_info{                 // CETI
	char machine_uuid[DIGEST_SIZE*2];
	struct aik_user_info user_info;
	char pubkey_uuid[DIGEST_SIZE*2];
}__attribute__((packed));



static struct struct_elem_attr aik_cert_info_desc[]=
{
	{"machine_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"user_info",OS210_TYPE_ORGCHAIN,0,&aik_user_info_desc},
	{"pubkey_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

struct ca_cert{
	struct aik_cert_info reqinfo;
	char AIPubKey_uuid[DIGEST_SIZE*2];
}__attribute__((packed));

static struct struct_elem_attr ca_cert_desc[]=
{
	{"reqinfo",OS210_TYPE_ORGCHAIN,0,&aik_cert_info_desc},
	{"AIPubKey_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr tesi_sign_data_desc[] = 
{
	{"datalen",TPM_TYPE_UINT32,sizeof(UINT32),NULL},
	{"data",OS210_TYPE_DEFINE,sizeof(BYTE),"datalen"},
	{"signlen",TPM_TYPE_UINT32,sizeof(UINT32),NULL},
	{"sign",OS210_TYPE_DEFINE,sizeof(BYTE),"signlen"},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
static struct struct_elem_attr tpm_key_parms_desc[] = 
{
	{"algorithmID",TPM_TYPE_UINT32,sizeof(UINT32),NULL},
	{"encScheme",TPM_TYPE_UINT16,sizeof(UINT16),NULL},
	{"sigScheme",TPM_TYPE_UINT16,sizeof(UINT16),NULL},
	{"parmSize",TPM_TYPE_UINT32,sizeof(UINT32),NULL},
	{"parms",OS210_TYPE_DEFINE,1,"parmSize"},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

static struct struct_elem_attr tpm_identity_req_desc[] = 
{
	{"asymBlobSize",TPM_TYPE_UINT32,sizeof(UINT32),NULL},
	{"symBlobSize",TPM_TYPE_UINT32,sizeof(UINT32),NULL},
	{"asymAlgorithm",OS210_TYPE_ORGCHAIN,0,tpm_key_parms_desc},
	{"symAlgorithm",OS210_TYPE_ORGCHAIN,0,tpm_key_parms_desc},
	{"asymBlob",OS210_TYPE_DEFINE,1,"asymBlobSize"},
	{"symBlob",OS210_TYPE_DEFINE,1,"symBlobSize"},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

#endif
