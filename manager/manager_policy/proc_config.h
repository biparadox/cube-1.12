#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H

#define PROC_NAME	"manager_policy"


   // this proc has these memory_database:
   // IMGI:  the image list of this cloud
   // VM_I:  all th vm created by the cloud
   // PLAI:  this cloud's platform information
   // 

static char * main_proc_name="manager_policy";
static int  (*main_proc_initfunc)()=&manager_policy_init;

static PROCDB_INIT procdb_init_list[]=
{
	{"VM_I",&vm_info_memdb_init,0},
	{"IMGI",&image_info_memdb_init,0},
	{"PLAI",&platform_info_memdb_init,0},
	{"VM_P",&vm_policy_memdb_init,0},
	{"IMGP",&image_policy_memdb_init,0},
	{"PLAP",&platform_policy_memdb_init,0},
	{"PCRP",NULL,0},
	{"FILP",NULL,0},
	{NULL,NULL,0}
};

static PROC_INIT main_proc_initdata=
	{PROC_NAME,PROC_TYPE_MAIN,&manager_policy_init,NULL};

static PROC_INIT proc_init_list[]=
{
	{"manager_vm",PROC_TYPE_DECIDE,&manager_vm_init,&manager_vm_start},
	{"manager_image",PROC_TYPE_DECIDE,&manager_image_init,&manager_image_start},
	{"manager_platform",PROC_TYPE_DECIDE,&manager_platform_init,&manager_platform_start},
	{NULL,0,NULL,NULL}
};

#endif // PROC_CONFIG_H
