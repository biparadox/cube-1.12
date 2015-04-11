#ifndef MONITOR_PROCESS_FUNC_H
#define MONITOR_PROCESS_FUNC_H

static struct struct_elem_attr share_data_desc[]=
{
    {"uuid",OS210_TYPE_STRING,64,NULL},
    {"server_name",OS210_TYPE_ESTRING,80,NULL},
    {"service",OS210_TYPE_ESTRING,80,NULL},
    {"server_addr",OS210_TYPE_ESTRING,80,NULL},
    {"flag",OS210_TYPE_INT,4,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

// init function
int json_port_init(void * proc,void * para);
int json_port_start(void * proc,void * para);


#endif
