#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H

#define PROC_NAME	"interface_server"


   // this proc has these memory_database:
   // 
static char * main_proc_name="interface_server";
static int  (*main_proc_initfunc)()=&interface_server_init;

static PROCDB_INIT procdb_init_list[]=
{
	{NULL,NULL,0}
};


static PROC_INIT proc_init_list[]=
{
        {"json_port",PROC_TYPE_MONITOR,&json_port_init,&json_port_start},
        {NULL,0,NULL,NULL}
};

#endif // PROC_CONFIG_H
