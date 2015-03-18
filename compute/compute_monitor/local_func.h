#ifndef LOCAL_FUNC_H
#define LOCAL_FUNC_H

void * build_compute_policy(char * uuid,char * hostname);
int proc_send_reqcmd(void * sub_proc,char * receiver,void * para);
int proc_send_compute_localinfo(void *sub_proc,void * message, void * para); 

#endif
