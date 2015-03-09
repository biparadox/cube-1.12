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

static PROC_INIT main_proc_initdata=
	{PROC_NAME,PROC_TYPE_MAIN,&trust_manager_init,NULL,main_state_name,main_func_name};

/*
extern int aik_process_init(void * sub_proc,void * para);
extern int aik_process_start(void * sub_proc,void * para);

extern int aik_casign_init(void * sub_proc,void * para);
extern int aik_casign_start(void * sub_proc,void * para);
*/

static PROC_INIT proc_init_list[]=
{
	{"aik_client",PROC_TYPE_MONITOR,&proc_aikclient_init,&proc_aikclient_start,proc_aikclient_state_name,proc_aikclient_func_name},
	{NULL,0,NULL,NULL}
};

static char * default_local_port=NULL; 
static char * default_remote_port=NULL; 

#endif // PROC_CONFIG_H
