
#ifndef FILE_RECEIVER_FUNC_H
#define FILE_RECEIVER_FUNC_H

int file_dealer_init(void * sub_proc,void * para);
int file_dealer_start(void * sub_proc,void * para);
struct timeval time_val={0,50*1000};

#endif
