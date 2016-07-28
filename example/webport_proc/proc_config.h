#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H

static PROCDB_INIT procdb_init_list[]=
{
	{"LOGI",&general_lib_init,&connect_login_desc,&general_lib_ops},
	{"RETC",NULL,&connect_return_desc,NULL},
	{NULL,NULL,NULL,NULL}
};

#endif // PROC_CONFIG_H
