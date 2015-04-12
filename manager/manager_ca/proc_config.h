#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H

#define PROC_NAME	"trust_manager_ca"


   // this proc has these memory_database:
   // IMGI:  the image list of this cloud
   // VM_I:  all th vm created by the cloud
   // PLAI:  this cloud's platform information
   // 

static char * main_proc_name="trust_manager_ca";
static int  (*main_proc_initfunc)()=&trust_manager_init;

static PROCDB_INIT procdb_init_list[]=
{
	{"VM_T",&vtpm_memdb_init,NULL,NULL},
	{"PUBK",&public_key_memdb_init,NULL,NULL},
	{"BLBK",&null_init_func,NULL,NULL},
	{"LOGC",&login_name_memdb_init,&connect_login_desc,&general_lib_ops},
	{"RETC",NULL,&connect_return_desc,NULL},
	{NULL,NULL,0}
};

static PROC_INIT proc_init_list[]=
{
	{"aik_casign",PROC_TYPE_CONTROL,&aik_casign_init,&aik_casign_start},
	{"ca_verify",PROC_TYPE_DECIDE,&ca_verify_init,&ca_verify_start},
	{NULL,0,NULL,NULL}
};

#endif // PROC_CONFIG_H
