#ifndef TESI_STRUCT_DESC_H
#define TESI_STRUCT_DESC_H

#include "../include/struct_deal.h"

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
