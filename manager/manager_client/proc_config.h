#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H

#define PROC_NAME	"trust_client"


   // this proc has these memory_database:
   // IMGI:  the image list of this cloud
   // VM_I:  all th vm created by the cloud
   // PLAI:  this cloud's platform information
   // 

static PROCDB_INIT procdb_init_list[]=
{
	{"VM_T",&vtpm_memdb_init,0},
	{"PUBK",&public_key_memdb_init,0},
	{"BLBK",&wrapped_key_memdb_init,0},
	{NULL,NULL,0}
};

static char * main_proc_name="trust_client";
static int  (*main_proc_initfunc)()=&trust_manager_init;

static PROC_INIT proc_init_list[]=
{
	{"aik_client",PROC_TYPE_MONITOR,&proc_aikclient_init,&proc_aikclient_start},
	{NULL,0,NULL,NULL}
};

#endif // PROC_CONFIG_H
