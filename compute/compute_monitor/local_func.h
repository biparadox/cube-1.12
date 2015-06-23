#ifndef LOCAL_FUNC_H
#define LOCAL_FUNC_H

#include "../include/vmlist.h"
#include "../include/vmlist_desc.h"
#include "../include/vm_policy.h"
#include "../include/vm_policy_desc.h"
#include "trust_template.h"
#include "trust_template_desc.h"

static struct struct_elem_attr share_data_desc[]=
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"proc_name",OS210_TYPE_ESTRING,DIGEST_SIZE*2,NULL},
	{"host_name",OS210_TYPE_ESTRING,DIGEST_SIZE*2,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};
typedef struct procdb_init_parameter
{
	char * name;
	int (*init)(char *,void *); 
	void * record_desc;
	void * recordlib_ops;
}PROCDB_INIT;

static __inline__ int null_init_func(char * type, void * para) {return 0;};

static PROCDB_INIT procdb_init_list[]=
{
	{"VM_I",&null_init_func,&vminfo_desc,&general_lib_ops},
	{"PLAI",&null_init_func,&platform_info_desc,&general_lib_ops},
	{"PCRP",&null_init_func,NULL,&general_lib_ops},
	{"VM_P",&null_init_func,&vm_policy_desc,&general_lib_ops},
	{"PLAP",&null_init_func,&vm_policy_desc,&general_lib_ops},
//	{"FILP",&null_init_func,NULL,&general_lib_ops},
	{"TF_I",&null_init_func,&trust_file_info_desc,&general_lib_ops},
	{"TFLI",&null_init_func,&trust_file_list_desc,&general_lib_ops},
	{"TDLI",&null_init_func,&trust_digest_list_desc,&general_lib_ops},
	{"TFAI",&null_init_func,&trust_file_array_desc,&general_lib_ops},
	{"TFPP",&null_init_func,&trust_file_pcr_policy_desc,&general_lib_ops},
	{"TPTP",&null_init_func,&trust_policy_template_desc,&general_lib_ops},
	{"TPDP",&null_init_func,&trust_policy_define_desc,&general_lib_ops},
	{"TASI",&null_init_func,&trust_arch_site_desc,&general_lib_ops},
	{"TAFI",&null_init_func,&trust_arch_frame_desc,&general_lib_ops},
	{"TA_P",&null_init_func,&trust_arch_policy_desc,&general_lib_ops},
	{NULL,NULL,NULL,NULL}
};

void * build_compute_policy(char * uuid,char * hostname);
int proc_send_reqcmd(void * sub_proc,char * receiver,void * para);
int proc_send_compute_localinfo(void *sub_proc,void * message); 

#endif
