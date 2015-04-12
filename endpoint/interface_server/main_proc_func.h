#ifndef MAIN_PROC_FUNC_H
#define MAIN_PROC_FUNC_H

int interface_server_init();

int vm_info_memdb_init();
int image_info_memdb_init();
int platform_info_memdb_init();
int vm_policy_memdb_init();
int pcr_policy_memdb_init();
int file_policy_memdb_init();

int json_port_init(void * sub_proc,void * para);
int json_port_start(void * sub_proc,void * para);

#endif
