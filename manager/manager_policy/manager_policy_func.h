#ifndef MANAGER_POLICY_FUNC_H
#define MANAGER_POLICY_FUNC_H

int manager_policy_init(void * proc);

int vm_info_memdb_init();
int image_info_memdb_init();
int vm_policy_memdb_init();
int pcr_policy_memdb_init();
int policy_file_memdb_init();


#endif
