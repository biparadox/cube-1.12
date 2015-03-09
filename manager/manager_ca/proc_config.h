#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H

#define PROC_NAME	"trust_manager_ca"


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
	{"aik_casign",PROC_TYPE_CONTROL,&aik_casign_init,&aik_casign_start,aik_casign_state_name,aik_casign_func_name},
	{"ca_verify",PROC_TYPE_DECIDE,&ca_verify_init,&ca_verify_start,ca_verify_state_name,ca_verify_func_name},
	{NULL,0,NULL,NULL}
};

static char * default_local_port=NULL; 
static char * default_remote_port=NULL; 

#endif // PROC_CONFIG_H
