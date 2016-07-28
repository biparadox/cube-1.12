#ifndef HUB_MESSAGE_EXPAND_H
#define HUB_MESSAGE_EXPAND_H


// plugin's init func and kickstart func
int message_expand_init(void * sub_proc,void * para);
int message_expand_start(void * sub_proc,void * para);
struct timeval time_val={0,50*1000};

#endif
