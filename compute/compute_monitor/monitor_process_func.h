#ifndef VERIFIER_IMAGE_FUNC_H
#define VERIFIER_IMAGE_FUNC_H

static struct struct_elem_attr share_data_desc[]=
{
	{"username",OS210_TYPE_ESTRING,80,NULL},
	{"userpass",OS210_TYPE_ESTRING,80,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

enum sub_proc_state
{
	PROC_VMMONITOR_INIT=0x1000,
	PROC_VMMONITOR_SLEEP,
	PROC_VMMONITOR_FAIL,
};

static NAME2VALUE subproc_state_list[]=
{
	{"init",PROC_VMMONITOR_INIT},
	{"sleep",PROC_VMMONITOR_SLEEP},
	{"fail",PROC_VMMONITOR_FAIL},
	{NULL,0}
};

// init function
int monitor_process_init(void * proc,void * para);
int monitor_process_start(void * proc,void * para);
/*
int process_monitor_vm(void * proc,void *para );
int process_monitor_image(void * proc,void * para);
int process_monitor_platform(void * proc, void * para);
*/
#endif
