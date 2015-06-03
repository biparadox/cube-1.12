#ifndef MAIN_PROC_FUNC_H
#define MAIN_PROC_FUNC_H
#include "manager_image_func.h"
#include "manager_vm_func.h"
#include "manager_platform_func.h"

int manager_policy_init();

int vm_info_memdb_init();
int image_info_memdb_init();
int platform_info_memdb_init();
int vm_policy_memdb_init();
int image_policy_memdb_init();
int platform_policy_memdb_init();
#endif
