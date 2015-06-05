#ifndef MAIN_PROC_FUNC _H
#define MAIN_PROC_FUNC_H
#include "local_func.h"
#include "../include/vmlist_desc.h"
#include "../include/vm_policy_desc.h"
#include "monitor_process_func.h"

int controller_monitor_init();

int platform_info_memdb_init(char * type, void * para);
int image_info_memdb_init(char * type,void * para);
int vm_info_memdb_init(char * type,void * para);
int image_policy_memdb_init(char * type,void * para);
int vm_policy_memdb_init(char * type,void * para);
int platform_policy_memdb_init(char * type,void * para);

#endif
