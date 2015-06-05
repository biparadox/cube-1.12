#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H

#define PROC_NAME	"controller_monitor"

   // this proc has these memory_database:
   // IMGI:  the image list of this cloud
   // VM_I:  all th vm created by the cloud
   // PLAI:  this cloud's platform information

static char * main_proc_name="controller_monitor";
static int  (*main_proc_initfunc)()=&controller_monitor_init;

static PROCDB_INIT procdb_init_list[]=
{
	{"IMGI",&image_info_memdb_init,&image_info_desc,&general_lib_ops},
	{"VM_I",&vm_info_memdb_init,&vminfo_desc,&general_lib_ops},
	{"PLAI",&null_init_func,&platform_info_desc,&general_lib_ops},
	{"PCRP",NULL,NULL,NULL},
	{"IMGP",&null_init_func,&vm_policy_desc,&general_lib_ops},
	{"VM_P",&null_init_func,&vm_policy_desc,&general_lib_ops},
	{"PLAP",&null_init_func,&vm_policy_desc,&general_lib_ops},
	{NULL,NULL,NULL,NULL}
};

static PROC_INIT proc_init_list[]=
{
	{"monitor_process",PROC_TYPE_MONITOR,&monitor_process_init,&monitor_process_start},
	{NULL,0,NULL,NULL}
};

#endif // PROC_CONFIG_H
