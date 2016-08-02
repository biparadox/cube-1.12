#ifndef KEY_STORAGE_FUNC_H
#define KEY_STORAGE_FUNC_H


// plugin's init func and kickstart func
int key_storage_init(void * sub_proc,void * para);
int key_storage_start(void * sub_proc,void * para);
struct timeval time_val={0,50*1000};

#endif
