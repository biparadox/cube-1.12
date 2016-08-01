#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H
#include "vm_policy_desc.h"
#include "session_msg.h"
#include "user_info.h"

static PROCDB_INIT procdb_init_list[]=
{
	{"EEIE",NULL,&expand_extra_info_desc,NULL},
	{"USNE",NULL,&user_name_expand_desc,NULL},
	{"U2AL",&null_init_func,&user_addr_list_desc,&general_lib_ops},
	{"MSGD",&null_init_func,&session_msg_desc,&general_lib_ops},
	{"UL_I",&general_lib_init,&user_info_list_desc,&general_lib_ops},
	{"LOGI",&general_lib_init,&connect_login_desc,&general_lib_ops},			
	{"RETC",NULL,&connect_return_desc,NULL},			
	{"FILS",&null_init_func,&policyfile_store_desc,&general_lib_ops},
	{"FILQ",NULL,&policyfile_req_desc,NULL},
	{NULL,NULL,NULL,NULL}
};

#endif // PROC_CONFIG_H
