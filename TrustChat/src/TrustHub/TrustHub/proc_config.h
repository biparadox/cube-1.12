#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H

#include "session_msg.h"
#include "user_info.h"
#include "tesi_key.h"
#include "tesi_key_desc.h"
#include "vtpm_desc.h"
#include "tesi_aik_struct.h"

static PROCDB_INIT procdb_init_list[]=
{
	{"VM_T",&null_init_func,&vtpm_info_desc,&general_lib_ops},
	{"PUBK",&null_init_func,&publickey_desc,&general_lib_ops},
	{"BLBK",&null_init_func,&wrappedkey_desc,&general_lib_ops},
	{"USRI",&general_uuid_lib_init,&aik_user_info_desc,&general_lib_ops},
	{"NKLD",&null_init_func,&node_key_list_desc,&general_lib_ops},
	{"LKLD",&null_init_func,&node_key_list_desc,&general_lib_ops},
	{"CERI",&null_init_func,&aik_cert_info_desc,&general_lib_ops},
	{"KREC",&null_init_func,&key_request_cmd_desc,&general_lib_ops},
	{"LOGI",NULL,&login_info_desc,NULL},
	{"USNE",NULL,&user_name_expand_desc,NULL},
	{NULL,NULL,NULL,NULL}
};
/*
static PROC_INIT proc_init_list[]=
{
	{"aik_client",PROC_TYPE_DECIDE,&proc_aikclient_init,&proc_aikclient_start},
	{"file_receiver",PROC_TYPE_MONITOR,&file_receiver_init,&file_receiver_start},
	{"key_manage",PROC_TYPE_MONITOR,&key_manage_init,&key_manage_start},
	{"hub_bind",PROC_TYPE_MONITOR,&hub_bind_init,&hub_bind_start},
	{NULL,0,NULL,NULL}
};
*/

#endif // PROC_CONFIG_H
