#ifndef PROC_CONFIG_H
#define PROC_CONFIG_H
#include "session_msg.h"
#include "user_info.h"
#include "tesi_key.h"
#include "tesi_key_desc.h"
#include "vtpm_desc.h"
#include "tesi_aik_struct.h"
#include "vm_policy_desc.h"

static PROCDB_INIT procdb_init_list[]=
{
	{"VM_T",&null_init_func,&vtpm_info_desc,&general_lib_ops},
	{"PUBK",&null_init_func,&publickey_desc,&general_lib_ops},
	{"BLBK",&null_init_func,&wrappedkey_desc,&general_lib_ops},
	{"USRI",&null_init_func,&aik_user_info_desc,&general_lib_ops},
	{"CERI",&null_init_func,&aik_cert_info_desc,&general_lib_ops},
	{"NKLD",&null_init_func,&node_key_list_desc,&general_lib_ops},
	{"KREC",&null_init_func,&key_request_cmd_desc,&general_lib_ops},
	{"FILS",&null_init_func,&policyfile_store_desc,&general_lib_ops},
	{NULL,NULL,NULL,NULL}
};

#endif // PROC_CONFIG_H
