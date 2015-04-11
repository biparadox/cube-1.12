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
	{"VM_P",&image_policy_memdb_init,0},
	{"PCRP",&pcr_policy_memdb_init,0},
	{"PCRI",&pcr_info_memdb_init,0},
	{"FILP",&file_policy_memdb_init,0},
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
