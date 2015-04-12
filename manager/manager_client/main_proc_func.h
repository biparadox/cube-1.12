#ifndef MAIN_PROC_FUNC_H
#define MAIN_PROC_FUNC_H

int client_manager_init();

int public_key_memdb_init();
int vtpm_memdb_init();

int proc_aikclient_init(void * sub_proc,void * para);
int proc_aikclient_start(void * sub_proc,void * para);

#endif
