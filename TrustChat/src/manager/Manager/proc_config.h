#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H
#include "session_msg.h"
#include "user_info.h"
#include "policy_info.h"

static PROCDB_INIT procdb_init_list[]=
{
	{"EEIE",NULL,&expand_extra_info_desc,NULL},
	{"USNE",NULL,&user_name_expand_desc,NULL},
	{"U2AL",&null_init_func,&user_addr_list_desc,&general_lib_ops},
	{"MSGD",&null_init_func,&session_msg_desc,&general_lib_ops},
	{"UL_I",&null_init_func,&user_info_list_desc,&general_lib_ops},
	{"LOGI",NULL,&login_info_desc,NULL},			
	{"POLI",&null_init_func,&policy_rule_desc,&general_lib_ops},			
	{"RETC",NULL,&connect_return_desc,NULL},			
	{NULL,NULL,NULL,NULL}
};

#endif // PROC_CONFIG_H
