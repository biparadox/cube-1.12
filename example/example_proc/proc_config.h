#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H


static char * main_proc_name="example_proc";
static int  (*main_proc_initfunc)()=&example_proc_init;

static PROCDB_INIT procdb_init_list[]=
{
	{NULL,NULL,NULL,NULL}
};

static PROC_INIT proc_init_list[]=
{
	{"echo_plugin",PROC_TYPE_DECIDE,&echo_plugin_init,&echo_plugin_start},
	{NULL,0,NULL,NULL}
};

#endif // PROC_CONFIG_H
