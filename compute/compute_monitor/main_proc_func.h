#ifndef MAIN_PROC_FUNC_H
#define MAIN_PROC_FUNC_H

#include "../include/vmlist_desc.h"
#include "../include/vm_policy_desc.h"
#include "monitor_process_func.h"

int compute_monitor_init();

int image_policy_memdb_init();
int vm_policy_memdb_init();
int platform_policy_memdb_init();
int platform_info_memdb_init();
int pcr_policy_memdb_init();
int file_policy_memdb_init();

#endif
