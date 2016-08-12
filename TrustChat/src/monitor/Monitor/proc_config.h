#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H
#include "session_msg.h"
#include "user_info.h"
#include "vm_policy_desc.h"

static PROCDB_INIT procdb_init_list[]=
{
	{"EEIE",NULL,&expand_extra_info_desc,NULL},
	{"USNE",NULL,&user_name_expand_desc,NULL},
	{"MSGD",&null_init_func,&session_msg_desc,&general_lib_ops},
	{"U2AL",&null_init_func,&user_addr_list_desc,&general_lib_ops},
	{"MESS",&null_init_func,&session_msg_desc,&general_lib_ops},
	{"LOGI",NULL,&login_info_desc,NULL},			
	{"UL_I",&general_lib_init,&user_info_list_desc,&general_lib_ops},
	{"RETC",NULL,&connect_return_desc,NULL},			
	{"REQC",NULL,&request_cmd_desc,NULL},			
	{"FILS",&null_init_func,&policyfile_store_desc,&general_lib_ops},
	{NULL,NULL,NULL,NULL}
};

#endif // PROC_CONFIG_H
