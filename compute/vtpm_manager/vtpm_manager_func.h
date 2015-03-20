#ifndef VTPM_MANAGER_FUNC_H
#define VTPM_MANAGER_FUNC_H

enum proc_running_state
{
	PROC_LOCAL_INIT=0,
	PROC_LOCAL_TPMOPEN,
	PROC_LOCAL_INITTPM,
	PROC_LOCAL_LOADLOCALTPMINFO,
	PROC_LOCAL_VTPMSERVERLISTEN,
};

enum proc_vtpm_channel_state
{
	CHANNEL_LOCAL_VTPM_REQ=10,
	CHANNEL_LOCAL_VTPM_START,
	CHANNEL_LOCAL_VTPM_INIT,
	CHANNEL_LOCAL_VTPM_GENKEYPAIR,
	CHANNEL_LOCAL_VTPM_SENDKEYPAIR,
};

static struct struct_elem_attr share_data_desc[]=
{
	{"username",OS210_TYPE_ESTRING,80,NULL},
	{"userpass",OS210_TYPE_ESTRING,80,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};


int blob_key_memdb_init();
int public_key_memdb_info();
int vtpm_info_memdb_init();
int process_vm_message(void * message_box,void * conn);

#endif
