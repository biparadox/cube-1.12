#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H


static char * main_proc_name="bind_server";
static int  (*main_proc_initfunc)()=&bind_server_init;

static PROCDB_INIT procdb_init_list[]=
{
	{"VM_T",&null_init_func,&vtpm_info_desc,&general_lib_ops},
	{"PUBK",&null_init_func,&publickey_desc,&general_lib_ops},
	{"BLBK",&null_init_func,&wrappedkey_desc,&general_lib_ops},
	{"USRI",&general_uuid_lib_init,&aik_user_info_desc,&general_lib_ops},
	{"CERI",&null_init_func,&aik_cert_info_desc,&general_lib_ops},
	{"KREC",&null_init_func,&key_request_cmd_desc,&general_lib_ops},
//	{"TBCE",NULL,&publickey_desc,NULL},
	{NULL,NULL,NULL,NULL}
};

static PROC_INIT proc_init_list[]=
{
	{"aik_client",PROC_TYPE_MONITOR,&proc_aikclient_init,&proc_aikclient_start},
	{"key_response",PROC_TYPE_MONITOR,&key_response_init,&key_response_start},
	{"server_unbind",PROC_TYPE_MONITOR,&server_unbind_init,&server_unbind_start},
	{NULL,0,NULL,NULL}
};

#endif // PROC_CONFIG_H
