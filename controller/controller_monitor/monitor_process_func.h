#ifndef MONITOR_PROCESS_FUNC_H
#define MONITOR_PROCESS_FUNC_H

// init function
int monitor_process_init(void * proc,void * para);
int monitor_process_start(void * sub_proc,void * para);

int process_monitor_vm(void * proc,void *para );
int process_monitor_image(void * proc,void * para);
int process_monitor_platform(void * proc, void * para);
#endif
