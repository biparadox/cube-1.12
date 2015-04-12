#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H

   // this proc has these memory_database:
   // IMGI:  the image list of this cloud
   // VM_I:  all th vm created by the cloud
   // PLAI:  this cloud's platform information
   // 

static char * main_proc_name="trust_client";
static int  (*main_proc_initfunc)()=&client_manager_init;

static PROCDB_INIT procdb_init_list[]=
{
	{"VM_T",&vtpm_memdb_init,NULL,NULL},
	{"PUBK",&public_key_memdb_init,NULL,NULL},
	{"BLBK",&null_init_func,NULL,NULL},
	{NULL,NULL,0}
};


static PROC_INIT proc_init_list[]=
{
	{"aik_client",PROC_TYPE_MONITOR,&proc_aikclient_init,&proc_aikclient_start},
	{NULL,0,NULL,NULL}
};

#endif // PROC_CONFIG_H
