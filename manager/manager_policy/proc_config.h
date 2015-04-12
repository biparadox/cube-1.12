#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H

static char * main_proc_name="manager_policy";
static int  (*main_proc_initfunc)()=&manager_policy_init;

static PROCDB_INIT procdb_init_list[]=
{
	{"VM_I",&vm_info_memdb_init,NULL,NULL},
	{"IMGI",&image_info_memdb_init,NULL,NULL},
	{"PLAI",&platform_info_memdb_init,NULL,NULL},
	{"VM_P",&vm_policy_memdb_init,NULL,NULL},
	{"IMGP",&image_policy_memdb_init,NULL,NULL},
	{"PLAP",&platform_policy_memdb_init,NULL,NULL},
	{"PCRP",NULL,NULL,NULL},
	{"FILP",NULL,NULL,NULL},
	{NULL,NULL,0}
};

static PROC_INIT proc_init_list[]=
{
	{"manager_vm",PROC_TYPE_DECIDE,&manager_vm_init,&manager_vm_start},
	{"manager_image",PROC_TYPE_DECIDE,&manager_image_init,&manager_image_start},
	{"manager_platform",PROC_TYPE_DECIDE,&manager_platform_init,&manager_platform_start},
	{NULL,0,NULL,NULL}
};

#endif // PROC_CONFIG_H
