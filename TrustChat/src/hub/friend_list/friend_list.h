#ifndef FRIEND_LIST_H
#define FRIEND_LIST_H

// plugin's init func and kickstart func
int friend_list_init(void * sub_proc,void * para);
int friend_list_start(void * sub_proc,void * para);
struct timeval time_val={0,50*1000};

#endif
