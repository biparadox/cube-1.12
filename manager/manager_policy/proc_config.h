#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H

static char * main_proc_name="manager_policy";
static int  (*main_proc_initfunc)()=&manager_policy_init;

static PROCDB_INIT procdb_init_list[]=
{
	{"IMGI",&null_init_func,&image_info_desc,&general_lib_ops},
	{"VM_I",&null_init_func,&vminfo_desc,&general_lib_ops},
	{"PLAI",&null_init_func,&platform_info_desc,&general_lib_ops},
	{"PCRP",&null_init_func,NULL,&general_lib_ops},
	{"IMGP",&null_init_func,&vm_policy_desc,&general_lib_ops},
	{"VM_P",&null_init_func,&vm_policy_desc,&general_lib_ops},
	{"PLAP",&null_init_func,&vm_policy_desc,&general_lib_ops},
	{"TREI",NULL,&userhostvminfo_desc,NULL},
	{"EEIE",NULL,&expand_extra_info_desc,NULL},
	{"FILP",NULL,NULL,NULL},
	{NULL,NULL,NULL,NULL}
};

static PROC_INIT proc_init_list[]=
{
	{"tree_info",PROC_TYPE_MONITOR,&tree_info_init,&tree_info_start},
	{"vm_find_host",PROC_TYPE_MONITOR,&vm_find_host_init,&vm_find_host_start},
	{"manager_vm",PROC_TYPE_MONITOR,&manager_vm_init,&manager_vm_start},
	{"manager_image",PROC_TYPE_MONITOR,&manager_image_init,&manager_image_start},
	{"manager_platform",PROC_TYPE_MONITOR,&manager_platform_init,&manager_platform_start},
	{NULL,0,NULL,NULL}
};

#endif // PROC_CONFIG_H
