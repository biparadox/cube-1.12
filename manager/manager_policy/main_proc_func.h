#ifndef MAIN_PROC_FUNC_H
#define MAIN_PROC_FUNC_H


int manager_policy_init();

int vm_info_memdb_init();
int image_info_memdb_init();
int platform_info_memdb_init();
int vm_policy_memdb_init();
int image_policy_memdb_init();
int platform_policy_memdb_init();

int manager_vm_init(void * sub_proc,void * para);
int manager_vm_start(void * sub_proc,void * para);

int manager_image_init(void * sub_proc,void * para);
int manager_image_start(void * sub_proc,void * para);

int manager_platform_init(void * sub_proc,void * para);
int manager_platform_start(void * sub_proc,void * para);

#endif
