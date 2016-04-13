#ifndef MAIN_PROC_FUNC_H
#define MAIN_PROC_FUNC_H
#include "../include/vtpm_struct.h"
#include "../include/vtpm_desc.h"
#include "trust_bind_func.h"
//#include "aik_process_func.h"

int test_bind_init();

// aik_casign plugin's init func and kickstart func
/*
struct expand_bind_info
{
	UINT32 data_size;
	char tag[4];
	char uuid[DIGEST_SIZE*2];
	char vtpm_uuid[DIGEST_SIZE*2];
        char bindkey_uuid[DIGEST_SIZE*2];
	char pubkey_uuid[DIGEST_SIZE*2];	
}__attribute__((packed));

static struct struct_elem_attr expand_bind_info_desc[]=
{
	{"data_size",OS210_TYPE_INT,sizeof(int ),NULL},
	{"tag",OS210_TYPE_STRING,4,NULL},   //should be TBCE
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"vtpm_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"bindkey_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"pubkey_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
*/

#endif
