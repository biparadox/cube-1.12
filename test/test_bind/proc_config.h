#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H


static char * main_proc_name="test_bind";
static int  (*main_proc_initfunc)()=&test_bind_init;

static PROCDB_INIT procdb_init_list[]=
{
//	{"VM_T",&vtpm_memdb_init,&vtpm_info_desc,&general_lib_ops},
	{"PUBK",&null_init_func,&publickey_desc,&general_lib_ops},
	{"BLBK",&null_init_func,&wrappedkey_desc,&general_lib_ops},
	{"TKCI",&null_init_func,&wrappedkey_desc,&general_lib_ops},
//	{"TBCE",NULL,&publickey_desc,NULL},
	{NULL,NULL,NULL,NULL}
};

static PROC_INIT proc_init_list[]=
{
	{"trust_bind",PROC_TYPE_MONITOR,&trust_bind_init,&trust_bind_start},
//	{"aik_client",PROC_TYPE_MONITOR,&proc_aikclient_init,&proc_aikclient_start},
	{NULL,0,NULL,NULL}
};

#endif // PROC_CONFIG_H
