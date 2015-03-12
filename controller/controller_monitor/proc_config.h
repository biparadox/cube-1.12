#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H

#define PROC_NAME	"controller_monitor"

   // this proc has these memory_database:
   // IMGI:  the image list of this cloud
   // VM_I:  all th vm created by the cloud
   // PLAI:  this cloud's platform information

static PROCDB_INIT procdb_init_list[]=
{
	{"IMGI",&image_info_memdb_init,0},
	{"VM_I",&vm_info_memdb_init,0},
	{"PLAI",&platform_info_memdb_init,0},
	{"PCRP",NULL,0},
	{"IMGP",&image_policy_memdb_init,0},
	{"VM_P",&vm_policy_memdb_init,0},
	{"PLAP",&platform_policy_memdb_init,0},
	{NULL,NULL,0}
};

static PROC_INIT main_proc_initdata=
	{PROC_NAME,PROC_TYPE_MAIN,&controller_monitor_init,NULL,main_state_name,main_func_name};

static PROC_INIT proc_init_list[]=
{
	{"monitor_process",PROC_TYPE_MONITOR,&monitor_process_init,&monitor_process_start,monitor_process_state_name,monitor_process_func_name},
	{NULL,0,NULL,NULL}
};

static char * default_local_port="local_client"; 
static char * default_remote_port="local_client"; 

#endif // PROC_CONFIG_H
