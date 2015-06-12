#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H

#define PROC_NAME	"verifier"


   // this proc has these memory_database:
   // IMGI:  the image list of this cloud
   // VM_I:  all th vm created by the cloud
   // PLAI:  this cloud's platform information
   // 

static char * main_proc_name="verifier";
static int  (*main_proc_initfunc)()=&verifier_init;
static PROCDB_INIT procdb_init_list[]=
{
	{"VM_P",&null_init_func,&vm_policy_desc,&general_lib_ops},
	{"PLAP",&null_init_func,&vm_policy_desc,&general_lib_ops},
	{"PCRP",&null_init_func,NULL,&general_lib_ops},
	{"PCRI",&null_init_func,&tcm_pcr_set_desc,&general_lib_ops},
	{"FILP",NULL,NULL,NULL},
	{"VERI",NULL,NULL,NULL},
	{NULL,NULL,0}
};


static PROC_INIT proc_init_list[]=
{
	{"verifier_image",PROC_TYPE_MONITOR,&verifier_image_init,&verifier_image_start},
	{"verifier_vm",PROC_TYPE_MONITOR,&verifier_vm_init,&verifier_vm_start},
	{"verifier_platform",PROC_TYPE_MONITOR,&verifier_platform_init,&verifier_platform_start},
	{NULL,0,NULL,NULL}
};


#endif // PROC_CONFIG_H
