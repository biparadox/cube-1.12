#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H

#define PROC_NAME	"interface_server"


   // this proc has these memory_database:
   // IMGI:  the image list of this cloud
   // VM_I:  all th vm created by the cloud
   // PLAI:  this cloud's platform information
   // 

static PROCDB_INIT procdb_init_list[]=
{
	{"VM_I",&vm_info_memdb_init,0},
	{"IMGI",&image_info_memdb_init,0},
	{"PLAI",&platform_info_memdb_init,0},
	{"VM_P",&vm_policy_memdb_init,0},
   	{"PCRP",&pcr_policy_memdb_init,0},
        {"FILP",&file_policy_memdb_init,0},
	{NULL,NULL,0}
};

static PROC_INIT main_proc_initdata=
    {PROC_NAME,PROC_TYPE_MAIN,&interface_server_init,NULL,interface_server_state_name,interface_server_func_name};


static PROC_INIT proc_init_list[]=
{
        {"json_port",PROC_TYPE_MONITOR,&json_port_init,&json_port_start,json_port_state_name,json_port_func_name},
        {NULL,0,NULL,NULL}
};

static char * default_local_port=NULL; 
static char * default_remote_port="trust_ca_server";
//static char * default_remote_port=NULL; 

#endif // PROC_CONFIG_H
