#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H

#define PROC_NAME	"compute_monitor"


static char * main_proc_name="compute_monitor";
static int  (*main_proc_initfunc)()=&compute_monitor_init;
   // this proc has these memory_database:
   // IMGI:  the image list of this cloud
   // VM_I:  all th vm created by the cloud
   // PLAI:  this cloud's platform information
   // 

static PROCDB_INIT procdb_init_list[]=
{
	{"IMGP",&image_policy_memdb_init,NULL,NULL},
	{"VM_P",&vm_policy_memdb_init,NULL,NULL},
	{"PLAI",&platform_info_memdb_init,NULL,NULL},
	{"PLAP",&platform_policy_memdb_init,NULL,NULL},
	{"PCRP",&pcr_policy_memdb_init,NULL,NULL},
	{"FILP",&file_policy_memdb_init,NULL,NULL},
	{NULL,NULL,NULL,NULL}
};

static PROC_INIT proc_init_list[]=
{
	{"monitor_process",PROC_TYPE_MONITOR,&monitor_process_init,&monitor_process_start},
	{NULL,0,NULL,NULL}
};

#endif // PROC_CONFIG_H
