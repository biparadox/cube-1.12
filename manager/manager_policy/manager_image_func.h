#ifndef MONITOR_PROCESS_FUNC_H
#define MONITOR_PROCESS_FUNC_H

struct struct_elem_attr share_data_desc[]=
{
	{"username",OS210_TYPE_ESTRING,80,NULL},
	{"userpass",OS210_TYPE_ESTRING,80,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

enum proc_monitor_state
{
	PROC_MONITOR_INIT=0x1000,
	PROC_MONITOR_SCAN,
	PROC_MONITOR_SLEEP,
	PROC_MONITOR_FAIL,
};

NAME2VALUE monitor_state_list[]=
{
	{"init",PROC_MONITOR_INIT},
	{"scan",PROC_MONITOR_SCAN},
	{"sleep",PROC_MONITOR_SLEEP},
	{"fail",PROC_MONITOR_FAIL},
	{NULL,0}
};

// init function
int manager_image_init(void * proc,void * para);
int manager_image_start(void * proc,void * para);
/*
int process_monitor_vm(void * proc,void *para );
int process_monitor_image(void * proc,void * para);
int process_monitor_platform(void * proc, void * para);
*/
#endif
