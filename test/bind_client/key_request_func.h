#ifndef KEY_REQUEST_FUNC_H
#define KEY_REQUEST_FUNC_H


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
	{"keyusage",OS210_TYPE_LONGLONG,sizeof(long long),NULL},
	{"keyflags",OS210_TYPE_LONGLONG,sizeof(long long),NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

// plugin's init func and kickstart func
int key_request_init(void * sub_proc,void * para);
int key_request_start(void * sub_proc,void * para);

#endif
