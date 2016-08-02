#ifndef KEY_REQUEST_FUNC_H
#define KEY_REQUEST_FUNC_H


// plugin's init func and kickstart func
int key_manage_init(void * sub_proc,void * para);
int key_manage_start(void * sub_proc,void * para);
struct timeval time_val={0,50*1000};

#endif
