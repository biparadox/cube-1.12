#ifndef MAIN_PROC_FUNC_H
#define MAIN_PROC_FUNC_H


int example_proc_init();


// aik_casign plugin's init func and kickstart func
int echo_plugin_init(void * sub_proc,void * para);
int echo_plugin_start(void * sub_proc,void * para);

#endif
