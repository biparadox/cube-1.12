#ifndef MAIN_PROC_FUNC_H
#define MAIN_PROC_FUNC_H
#include "../include/vm_policy_desc.h"
#include "../include/vmlist_desc.h"

int verifier_init();

int image_policy_memdb_init();
int platform_policy_memdb_init();
int vm_policy_memdb_init();
int pcr_policy_memdb_init();
int pcr_info_memdb_init();
int file_policy_memdb_init();

int verifier_image_init(void * sub_proc,void * para);
int verifier_image_start(void * sub_proc,void * para);

int verifier_platform_init(void * sub_proc,void * para);
int verifier_platform_start(void * sub_proc,void * para);

int verifier_vm_init(void * sub_proc,void * para);
int verifier_vm_start(void * sub_proc,void * para);

#endif
