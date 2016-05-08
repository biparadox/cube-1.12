#ifndef KEY_RESPONSE_FUNC_H
#define KEY_RESPONSE_FUNC_H


struct key_request_cmd
{
	char machine_uuid[DIGEST_SIZE*2];
	char *proc_name;
	UINT16 keyusage;
	UINT16 keyflags;
} __attribute__((packed));

static struct struct_elem_attr key_request_cmd_desc[]=
{
	{"machine_uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"proc_name",OS210_TYPE_ESTRING,DIGEST_SIZE*2,NULL},
	{"keyusage",TPM_TYPE_UINT16,0,NULL},
	{"keyflags",TPM_TYPE_UINT16,0,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

// plugin's init func and kickstart func
int key_response_init(void * sub_proc,void * para);
int key_response_start(void * sub_proc,void * para);

#endif
