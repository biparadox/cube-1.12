#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H


static char * main_proc_name="crypt_proc";
static int  (*main_proc_initfunc)()=&crypt_proc_init;

static PROCDB_INIT procdb_init_list[]=
{
	{"VM_T",&null_init_func,&vtpm_info_desc,&general_lib_ops},
	{"BLBK",&privkey_memdb_init,&wrappedkey_desc,&general_lib_ops},
	{"PUBK",&pubkey_memdb_init,&publickey_desc,&general_lib_ops},
	{"LOGC",NULL,&connect_login_desc,NULL},
	{"MSGD",NULL,&message_record_desc,NULL},
	{"KEYE",NULL,&expand_data_keyid_desc,NULL},
	{NULL,NULL,NULL,NULL}
};

static PROC_INIT proc_init_list[]=
{
	{"echo_plugin",PROC_TYPE_DECIDE,&echo_plugin_init,&echo_plugin_start},
	{"json_port",PROC_TYPE_MONITOR,&json_port_init,&json_port_start},
	{"trust_bind",PROC_TYPE_MONITOR,&trust_bind_init,&trust_bind_start},
	{"trust_unbind",PROC_TYPE_MONITOR,&trust_unbind_init,&trust_unbind_start},
	{NULL,0,NULL,NULL}
};

#endif // PROC_CONFIG_H
