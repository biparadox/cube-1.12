#ifndef ECHO_PLUGIN_FUNC_H
#define ECHO_PLUGIN_FUNC_H


// plugin's init func and kickstart func
int black_filter_init(void * sub_proc,void * para);
int black_filter_start(void * sub_proc,void * para);
struct timeval time_val={0,50*1000};

#endif
