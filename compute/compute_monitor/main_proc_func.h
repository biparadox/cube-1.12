#ifndef MAIN_PROC_FUNC_H
#define MAIN_PROC_FUNC_H

int compute_monitor_init();

int image_policy_memdb_init();
int vm_policy_memdb_init();
int platform_policy_memdb_init();
int platform_info_memdb_init();
int pcr_policy_memdb_init();
int file_policy_memdb_init();

int monitor_process_init(void * sub_proc,void * para);
int monitor_process_start(void * sub_proc,void * para);

#endif
