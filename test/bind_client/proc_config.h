#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H


static char * main_proc_name="bind_client";
static int  (*main_proc_initfunc)()=&test_bind_init;

static PROCDB_INIT procdb_init_list[]=
{
//	{"VM_T",&vtpm_memdb_init,&vtpm_info_desc,&general_lib_ops},
	{"PUBK",&null_init_func,&publickey_desc,&general_lib_ops},
	{"BLBK",&null_init_func,&wrappedkey_desc,&general_lib_ops},
	{"TKCI",&null_init_func,&wrappedkey_desc,&general_lib_ops},
	{"KREC",&null_init_func,&key_request_cmd_desc,&general_lib_ops},
//	{"TBCE",NULL,&publickey_desc,NULL},
	{NULL,NULL,NULL,NULL}
};

static PROC_INIT proc_init_list[]=
{
	{"client_bind",PROC_TYPE_MONITOR,&client_bind_init,&client_bind_start},
	{"key_request",PROC_TYPE_MONITOR,&key_request_init,&key_request_start},
	{"file_receiver",PROC_TYPE_MONITOR,&file_receiver_init,&file_receiver_start},
//	{"aik_client",PROC_TYPE_MONITOR,&proc_aikclient_init,&proc_aikclient_start},
	{NULL,0,NULL,NULL}
};

#endif // PROC_CONFIG_H
