#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H


static char * main_proc_name="test_ca";
static int  (*main_proc_initfunc)()=&test_ca_init;

static PROCDB_INIT procdb_init_list[]=
{
	{"VM_T",&vtpm_memdb_init,&vtpm_info_desc,&general_lib_ops},
	{"PUBK",&public_key_memdb_init,&publickey_desc,&general_lib_ops},
	{"BLBK",&null_init_func,&wrappedkey_desc,&general_lib_ops},
	{NULL,NULL,NULL,NULL}
};

static PROC_INIT proc_init_list[]=
{
	{"aik_casign",PROC_TYPE_MONITOR,&aik_casign_init,&aik_casign_start},
	{NULL,0,NULL,NULL}
};

#endif // PROC_CONFIG_H
