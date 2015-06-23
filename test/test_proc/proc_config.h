#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H


static char * main_proc_name="test_proc";
static int  (*main_proc_initfunc)()=&test_proc_init;

static PROCDB_INIT procdb_init_list[]=
{
	{"TIME",NULL,&expand_time_stamp_desc,NULL},
	{"LOGC",NULL,&connect_login_desc,NULL},
	{"RETC",NULL,&connect_return_desc,NULL},
	{NULL,NULL,NULL,NULL}
};

static PROC_INIT proc_init_list[]=
{
	{"echo_plugin",PROC_TYPE_DECIDE,&echo_plugin_init,&echo_plugin_start},
	{"json_port",PROC_TYPE_MONITOR,&json_port_init,&json_port_start},
	{"time_stamp",PROC_TYPE_MONITOR,&time_stamp_init,&time_stamp_start},
	{NULL,0,NULL,NULL}
};

#endif // PROC_CONFIG_H
