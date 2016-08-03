
#ifndef AIK_PROCESS_FUNC_H
#define AIK_PROCESS_FUNC_H

int aik_client_init(void * sub_proc,void * para);
int aik_client_start(void * sub_proc,void * para);
struct timeval time_val={0,50*1000};

#endif
