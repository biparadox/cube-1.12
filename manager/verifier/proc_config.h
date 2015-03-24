#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H

#define PROC_NAME	"verifier"


   // this proc has these memory_database:
   // IMGI:  the image list of this cloud
   // VM_I:  all th vm created by the cloud
   // PLAI:  this cloud's platform information
   // 

static PROCDB_INIT procdb_init_list[]=
{
	{"VM_P",&image_policy_memdb_init,0},
	{"PCRP",&pcr_policy_memdb_init,0},
	{"FILP",&file_policy_memdb_init,0},
	{NULL,NULL,0}
};

static PROC_INIT main_proc_initdata=
	{PROC_NAME,PROC_TYPE_MAIN,&verifier_init,NULL,main_state_name,main_func_name};

static PROC_INIT proc_init_list[]=
{
	{"verifier_image",PROC_TYPE_MONITOR,&verifier_image_init,&verifier_image_start,verifier_image_state_name,verifier_image_func_name},
	{"verifier_vm",PROC_TYPE_MONITOR,&verifier_vm_init,&verifier_vm_start,verifier_vm_state_name,verifier_vm_func_name},
	{"verifier_platform",PROC_TYPE_MONITOR,&verifier_platform_init,&verifier_platform_start,verifier_platform_state_name,verifier_platform_func_name},
	{NULL,0,NULL,NULL}
};

static char * default_local_port=NULL; 
static char * default_remote_port=NULL; 

#endif // PROC_CONFIG_H
