#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H


static char * main_proc_name="test_verify";
static int  (*main_proc_initfunc)()=&test_verify_init;

static PROCDB_INIT procdb_init_list[]=
{
	{"LOGC",&general_lib_init,&connect_login_desc,&general_lib_ops},
	{"RETC",NULL,&connect_return_desc,NULL},
	{NULL,NULL,NULL,NULL}
};

static PROC_INIT proc_init_list[]=
{
	{"login_verify",PROC_TYPE_MONITOR,&login_verify_init,&login_verify_start},
	{NULL,0,NULL,NULL}
};

#endif // PROC_CONFIG_H
