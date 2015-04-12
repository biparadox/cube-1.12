#ifndef MAIN_PROC_FUNC_H
#define MAIN_PROC_FUNC_H


int trust_manager_init();

int public_key_memdb_init();
int wrapped_key_memdb_init();
int vtpm_memdb_init();
int login_name_memdb_init();


// aik_casign plugin's init func and kickstart func
int aik_casign_init(void * sub_proc,void * para);
int aik_casign_start(void * sub_proc,void * para);

// ca_verify plugin's init func and kickstart func
int ca_verify_init(void * sub_proc,void * para);
int ca_verify_start(void * sub_proc,void * para);


#endif
