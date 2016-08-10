#ifndef SERVER_LOGIN_VERIFY_H
#define SERVER_LOGIN_VERIFY_H

int server_login_verify_init(void * sub_proc,void *para);
int server_login_verify_start(void * sub_proc,void *para);
struct timeval time_val={0,50*1000};
#endif
