#ifndef MS_SER_DB_H
#define MS_SER_DB_H

int ms_ser_db_init(void * sub_proc,void *para);
int ms_ser_db_start(void * sub_proc,void *para);
struct timeval time_val={0,50*1000};
#endif
